import Foundation
import Network
import NetworkExtension

/// Extension-only WireGuard transport. BoringTun provides the WireGuard
/// protocol codec; this class owns Apple packetFlow, routing, and UDP I/O.
/// All engine operations and lifecycle transitions run on one serial queue.
final class BoringTunTransport {
    private let queue = DispatchQueue(label: "com.gavindu.securityagent.boringtun")
    private weak var provider: NEPacketTunnelProvider?
    private var codec: BoringTunCodec?
    private let dnsResolver = AsyncUnderlayDNSResolver.shared
    // The DNS worker may outlive an aborted startup. Cancel callback
    // delivery on teardown; the singleton still owns its blocked worker.
    private var dnsCancellation: UnderlayDNSCancellation?
    // Queue-confined epoch invalidates callbacks after stop/restart.
    private var lifecycle = TunnelLifecycleGeneration()
    private var udp: NWConnection?
    private var tickTimer: DispatchSourceTimer?
    private var handshakeDeadline: DispatchSourceTimer?
    private var startupDeadline: DispatchSourceTimer?
    private var pathWaitDeadline: DispatchSourceTimer?
    // Queue-confined generation rejects timer callbacks from old wait episodes.
    private var pathWait = WireGuardPathWaitGeneration()
    private var startCompletion: ((Error?) -> Void)?
    private var active = false
    private var readingPackets = false
    private var receivingDatagram = false
    private var pendingSends = 0
    private let maxPendingSends = 256

    init(provider: NEPacketTunnelProvider) {
        self.provider = provider
    }

    func start(profile: ServerProfile, completion: @escaping (Error?) -> Void) {
        queue.async {
            guard !self.active else {
                completion(BoringTunError.initializationFailed)
                return
            }
            self.active = true
            let epoch = self.lifecycle.advance()
            self.startCompletion = completion
            self.armStartupDeadline(epoch: epoch)
            do {
                let validated = try profile.validated()
                // Enforce inside the extension, including already-persisted
                // full profiles; never install unproven 0/0 and ::/0 routes.
                guard TunnelRouteSafetyPolicy.permitsStart(validated.routeMode) else {
                    throw AgentConfigurationError.unverifiedFullTunnel
                }
                // Refuse accidental route expansion before DNS/FFI. The
                // same approved private plan is checked at installation.
                guard TunnelUnderlayPolicy.privateAgentSplitRoutes(
                    includedIPv4CIDRs: RouteMode.split.allowedIPs
                ) != nil else {
                    throw AgentConfigurationError.invalidSplitRoute
                }
                // Validate the outer UDP endpoint before any Keychain/Rust
                // codec allocation and before installing the inner IP routes.
                guard let components = URLComponents(string: "udp://\(validated.endpoint)"),
                      let host = components.host, !host.isEmpty,
                      let portNumber = components.port,
                      let port = Network.NWEndpoint.Port(rawValue: UInt16(portNumber)),
                      self.provider != nil else {
                    throw AgentConfigurationError.invalidEndpoint
                }
                if validated.routeMode == .split &&
                    !TunnelUnderlayPolicy.permitsLiteralEndpoint(
                        host: host, includedIPv4CIDRs: RouteMode.split.allowedIPs
                    ) {
                    throw AgentConfigurationError.unsafeUnderlayEndpoint
                }

                // Each explicit or previously authorized on-demand start
                // performs fresh preflight; no previous transport pin is
                // cached here. A ready connection retains its current pin.
                // Resolve outer UDP before installing inner routes. Brackets
                // are URLComponents formatting, not part of an IPv6 DNS name.
                let lookupHost = host.first == "[" && host.last == "]"
                    ? String(host.dropFirst().dropLast()) : host
                self.dnsCancellation = self.dnsResolver.resolve(
                    host: lookupHost, callbackQueue: self.queue
                ) { [weak self] result in
                    guard let self, self.active,
                          self.lifecycle.matches(epoch) else { return }
                    self.dnsCancellation = nil
                    switch result {
                    case .failure(let error):
                        // Preserve a redacted DNS-specific failure. Calling
                        // this a Rust initialization error is misleading:
                        // no BoringTun codec or inner route exists yet.
                        self.fail(error)
                    case .success(let addresses):
                        self.startResolved(profile: validated, addresses: addresses,
                                           port: port, epoch: epoch)
                    }
                }
            } catch {
                self.fail(error)
            }
        }
    }

    /// Exclusively on the engine queue, only for this startup epoch. The
    /// *same numeric IP* is used by network settings and the UDP NWConnection.
    private func startResolved(
        profile: ServerProfile, addresses: [String],
        port: Network.NWEndpoint.Port, epoch: UInt64
    ) {
        guard active, lifecycle.matches(epoch), let provider else { return }
        do {
            // DNS can complete after a preference mutation begins. Recheck
            // the journal and persisted profile before Rust/route allocation.
            guard SharedPreferenceWriteJournal.current.state == .clear,
                  SharedProfileStore.load() == profile else {
                throw AgentConfigurationError.preferenceRecoveryRequired
            }
            guard let pinnedHost = ResolvedUnderlayCandidatePolicy.selectPinnedAddress(
                addresses, includedIPv4CIDRs: RouteMode.split.allowedIPs
            ) else {
                throw AgentConfigurationError.unsafeUnderlayEndpoint
            }
            let secret = try SharedKeychain.existingIdentity()
            let psk = try SharedKeychain.optionalPreSharedKey()
            codec = try BoringTunCodec(
                privateKey: secret, serverKey: profile.publicKey, presharedKey: psk
            )
            // Force a typed numeric endpoint; never fall back to a DNS
            // .name host even if future resolver normalization changes.
            let destination: Network.NWEndpoint.Host
            if let address = Network.IPv4Address(pinnedHost) {
                destination = .ipv4(address)
            } else if let address = Network.IPv6Address(pinnedHost) {
                destination = .ipv6(address)
            } else {
                throw AgentConfigurationError.unsafeUnderlayEndpoint
            }
            let settings = try networkSettings(profile: profile, remoteHost: pinnedHost)
            provider.setTunnelNetworkSettings(settings) { [weak self] error in
                self?.queue.async {
                    guard let self, self.active,
                          self.lifecycle.matches(epoch) else { return }
                    if let error {
                        self.fail(error)
                        return
                    }
                    guard SharedPreferenceWriteJournal.current.state == .clear,
                          SharedProfileStore.load() == profile else {
                        self.fail(AgentConfigurationError.preferenceRecoveryRequired)
                        return
                    }
                    self.connect(host: destination, port: port)
                }
            }
        } catch {
            fail(error)
        }
    }

    /// An overall deadline also covers a missing native network-settings callback.
    /// This timer is independent of the shorter post-connection handshake bound.
    private func armStartupDeadline(epoch: UInt64) {
        startupDeadline?.cancel()
        let timer = DispatchSource.makeTimerSource(queue: queue)
        timer.schedule(deadline: .now() + .seconds(WireGuardStartupWatchdogPolicy.timeoutSeconds))
        timer.setEventHandler { [weak self] in
            guard let self, WireGuardStartupWatchdogPolicy.shouldExpire(
                active: self.active,
                pendingCompletion: self.startCompletion != nil,
                expectedGeneration: epoch,
                currentGeneration: self.lifecycle.current
            ) else { return }
            self.fail(BoringTunError.startupTimedOut)
        }
        startupDeadline = timer
        timer.resume()
    }

    private func networkSettings(
        profile: ServerProfile, remoteHost: String
    ) throws -> NEPacketTunnelNetworkSettings {
        // This builder is split-only. No dormant full-mode defaults or DNS
        // overrides can be reached by a future caller bypassing start().
        guard profile.routeMode == .split else {
            throw AgentConfigurationError.unverifiedFullTunnel
        }
        guard let routes = TunnelUnderlayPolicy.privateAgentSplitRoutes(
            includedIPv4CIDRs: RouteMode.split.allowedIPs
        ) else {
            throw AgentConfigurationError.invalidSplitRoute
        }
        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: remoteHost)
        settings.mtu = NSNumber(value: 1420)
        let ipv4 = NEIPv4Settings(addresses: ["10.8.0.2"], subnetMasks: ["255.255.255.255"])
        ipv4.includedRoutes = routes.map {
            NEIPv4Route(destinationAddress: $0.destinationAddress, subnetMask: $0.subnetMask)
        }
        settings.ipv4Settings = ipv4
        // Leave IPv6 and DNS settings absent so ordinary system traffic
        // remains outside this private IPv4 tunnel.
        return settings
    }

    private func connect(host: Network.NWEndpoint.Host, port: Network.NWEndpoint.Port) {
        guard active else { return }
        let epoch = lifecycle.current
        let connection = NWConnection(host: host, port: port, using: .udp)
        udp = connection
        connection.stateUpdateHandler = { [weak self] state in
            self?.queue.async { [weak self] in
                guard let self, self.active,
                      self.lifecycle.matches(epoch) else { return }
                self.connectionChanged(state)
            }
        }
        connection.start(queue: queue)

        let deadline = DispatchSource.makeTimerSource(queue: queue)
        deadline.schedule(deadline: .now() + .seconds(15))
        deadline.setEventHandler { [weak self] in
            guard let self, self.active, self.lifecycle.matches(epoch),
                  self.startCompletion != nil else { return }
            self.fail(BoringTunError.handshakeTimedOut)
        }
        handshakeDeadline = deadline
        deadline.resume()
    }

    private func connectionChanged(_ state: NWConnection.State) {
        guard active else { return }
        switch state {
        case .ready:
            // NWConnection readiness is not fresh Rust authentication.
            // Never re-enable the old data plane or cancel the wait guard
            // as a successful recovery. Tear down for a fresh authorized start.
            guard !pathWait.requiresFreshStartOnReady else {
                fail(BoringTunError.networkPathRevalidationRequired)
                return
            }
            cancelPathWaitDeadline()
            receiveDatagram()
            if tickTimer == nil {
                let timer = DispatchSource.makeTimerSource(queue: queue)
                timer.schedule(deadline: .now() + .milliseconds(100),
                               repeating: .milliseconds(100),
                               leeway: .milliseconds(20))
                let epoch = lifecycle.current
                timer.setEventHandler { [weak self] in
                    guard let self, self.active, self.lifecycle.matches(epoch),
                          self.pathWait.permitsEngineIO,
                          let codec = self.codec else { return }
                    do { try self.process(codec.tick()) }
                    catch { self.fail(error) }
                }
                tickTimer = timer
                timer.resume()
            }
            do {
                if let codec { try process(codec.forceHandshake()) }
            } catch {
                fail(error)
            }
        case .failed(let error):
            fail(error)
        case .cancelled:
            if active { fail(BoringTunError.stopped) }
        case .waiting:
            // Before authentication, handshakeDeadline already bounds startup.
            // An authenticated tunnel must never stay apparently connected
            // forever after its encrypted UDP underlay enters waiting.
            startPathWaitDeadlineIfNeeded()
        case .preparing, .setup:
            break
        @unknown default:
            fail(BoringTunError.initializationFailed)
        }
    }

    /// Bounded recovery only after a verified handshake completed. A fresh
    /// on-demand or manual restart re-resolves DDNS before any inner route.
    /// Pause old-session I/O and expose reasserting while waiting. Ready or
    /// timeout terminates this session; no transport-side retry is scheduled.
    private func startPathWaitDeadlineIfNeeded() {
        guard active, startCompletion == nil,
              let token = pathWait.beginWait() else { return }
        // Private chat requires the actual native connected status.
        provider?.reasserting = true
        let epoch = lifecycle.current
        let timer = DispatchSource.makeTimerSource(queue: queue)
        timer.schedule(deadline: .now() + .seconds(30))
        timer.setEventHandler { [weak self] in
            guard let self, self.active, self.lifecycle.matches(epoch),
                  self.pathWait.accepts(token) else { return }
            self.fail(BoringTunError.networkPathTimedOut)
        }
        pathWaitDeadline = timer
        timer.resume()
    }

    private func cancelPathWaitDeadline() {
        pathWait.invalidate()
        pathWaitDeadline?.cancel()
        pathWaitDeadline = nil
    }

    private func receiveDatagram() {
        guard active, pathWait.permitsEngineIO, let udp, !receivingDatagram else { return }
        receivingDatagram = true
        let epoch = lifecycle.current
        udp.receiveMessage { [weak self] packet, _, _, error in
            self?.queue.async { [weak self] in
                guard let self, self.active,
                      self.lifecycle.matches(epoch) else { return }
                self.receivingDatagram = false
                // Discard late datagrams from the interrupted session.
                guard self.pathWait.permitsEngineIO else { return }
                if let error {
                    self.fail(error)
                    return
                }
                if let packet, !packet.isEmpty, let codec = self.codec {
                    // A random/malformed UDP message must not crash or
                    // disable the VPN; discard authentication failures.
                    // Remote authentication errors can be discarded; a
                    // malformed *local* Rust C ABI result must tear down this
                    // session rather than vanish behind blanket try?.
                    var action: BoringTunAction?
                    do {
                        action = try codec.decapsulate(packet)
                    } catch {
                        let reason: WireGuardDatagramFailurePolicy.Reason
                        switch error {
                        case BoringTunError.invalidPacket:
                            reason = .malformedIncomingPacket
                        case BoringTunError.engineError:
                            reason = .authenticationRejected
                        case BoringTunError.invalidResponse:
                            reason = .malformedFFIResponse
                        default:
                            reason = .unexpectedLocalFailure
                        }
                        guard WireGuardDatagramFailurePolicy.disposition(for: reason) == .discard else {
                            self.fail(error)
                            return
                        }
                    }
                    if let action {
                        // Local UDP queue/packetFlow failures are never
                        // classified as unauthenticated remote rejections.
                        do { try self.process(action) } catch { self.fail(error); return }
                        // Upstream Tunn::decapsulate requires empty-input
                        // continuation after WriteToNetwork until Done.
                        if case .sendToNetwork = action {
                            do {
                                try codec.drainQueuedPackets { datagram in
                                    try self.process(.sendToNetwork(datagram))
                                }
                            } catch {
                                self.fail(error)
                                return
                            }
                        }
                    }
                    if codec.hasAuthenticatedHandshake && self.startCompletion != nil {
                        self.handshakeDeadline?.cancel()
                        self.handshakeDeadline = nil
                        // Only a fresh authenticated startup clears reasserting.
                        self.provider?.reasserting = false
                        self.finishStart(nil)
                        self.readPackets()
                    }
                }
                // A nil/empty, error-free NWConnection receive callback is
                // not a reason to re-arm in a tight serial-queue loop.
                // Positive UDP payloads continue at full receive throughput.
                if WireGuardReceiveRearmPolicy.needsBackoff(
                    receivedByteCount: packet?.count
                ) {
                    self.queue.asyncAfter(
                        deadline: .now() + .milliseconds(
                            WireGuardReceiveRearmPolicy.emptyReceiveDelayMilliseconds
                        )
                    ) { [weak self] in
                        guard let self, self.active,
                              self.lifecycle.matches(epoch) else { return }
                        self.receiveDatagram()
                    }
                } else {
                    self.receiveDatagram()
                }
            }
        }
    }

    private func process(_ action: BoringTunAction) throws {
        guard active, pathWait.permitsEngineIO else { throw BoringTunError.stopped }
        switch action {
        case .done:
            break
        case .sendToNetwork(let datagram):
            guard let udp else { throw BoringTunError.stopped }
            // Bounded async send backlog. A congested NWConnection must not
            // terminate the entire VPN: drop this encrypted datagram when
            // at capacity, but fail on corrupted local queue accounting.
            switch UDPBackpressurePolicy.decision(
                pendingSends: pendingSends, maxPendingSends: maxPendingSends
            ) {
            case .enqueue:
                break
            case .drop:
                return
            case .invalid:
                throw BoringTunError.engineError
            }
            // Keep eight of the 256 bounded UDP send slots available for
            // Rust BoringTun handshake/cookie/rekey while data bursts arrive.
            // Unknown or malformed wire messages remain an engine error.
            switch WireGuardControlHeadroomPolicy.decision(
                datagram: datagram, pendingSends: pendingSends,
                maxPendingSends: maxPendingSends, reservedControlSlots: 8
            ) {
            case .enqueue:
                break
            case .drop:
                return
            case .invalid:
                throw BoringTunError.engineError
            }
            pendingSends += 1
            let epoch = lifecycle.current
            udp.send(content: datagram, completion: .contentProcessed { [weak self] error in
                self?.queue.async { [weak self] in
                    guard let self, self.active,
                          self.lifecycle.matches(epoch) else { return }
                    self.pendingSends -= 1
                    if let error { self.fail(error) }
                }
            })
        case .writeIPv4(let packet):
            try deliverInnerPacket(packet, family: .ipv4, protocolFamily: AF_INET)
        case .writeIPv6(let packet):
            try deliverInnerPacket(packet, family: .ipv6, protocolFamily: AF_INET6)
        }
    }

    /// Local utun writes report a Boolean. A rejected write must propagate
    /// through process() to fail(error), not silently blackhole authenticated
    /// peer data or be confused with a discardable remote auth failure.
    /// Called only on this transport's serial Rust/packetFlow queue.
    private func deliverInnerPacket(
        _ packet: Data, family: IPPacketFamily, protocolFamily: Int32
    ) throws {
        guard let provider else { throw BoringTunError.stopped }
        do {
            try WireGuardInnerPacketDelivery.deliver(packet, family: family) { validated in
                provider.packetFlow.writePackets(
                    [validated], withProtocols: [NSNumber(value: protocolFamily)]
                )
            }
        } catch WireGuardInnerPacketDelivery.DeliveryError.writeRejected {
            throw BoringTunError.packetFlowWriteFailed
        }
    }

    private func readPackets() {
        guard active, pathWait.permitsEngineIO, !readingPackets, let provider else { return }
        readingPackets = true
        let epoch = lifecycle.current
        provider.packetFlow.readPackets { [weak self] packets, protocols in
            self?.queue.async { [weak self] in
                guard let self, self.active,
                      self.lifecycle.matches(epoch) else { return }
                self.readingPackets = false
                // No old-session packets may be encapsulated while waiting.
                guard self.pathWait.permitsEngineIO else { return }
                // Apple's packetFlow callback must supply one AF per packet.
                // Swift zip() silently truncates mismatched arrays; this is a
                // local utun contract failure, not remote Rust authentication.
                guard WireGuardPacketReadBatchPolicy.accepts(
                    packetCount: packets.count, protocolCount: protocols.count
                ) else {
                    self.fail(BoringTunError.packetFlowReadFailed)
                    return
                }
                // Only materialize lengths after count is capped. A huge
                // local utun batch must not starve rekey/tick/teardown work.
                guard WireGuardPacketReadBatchPolicy.acceptsPayloadLengths(
                    packets.map(\.count)
                ) else {
                    self.fail(BoringTunError.packetFlowReadFailed)
                    return
                }
                guard let codec = self.codec else {
                    self.fail(BoringTunError.stopped)
                    return
                }
                for (packet, proto) in zip(packets, protocols) {
                    // NSNumber.int32Value can wrap an invalid 64-bit AF into a
                    // supported 32-bit one. Fail the local OS callback instead
                    // of silently dropping or misclassifying the packet.
                    guard WireGuardReadProtocolPolicy.accepts(
                        proto, ipv4: AF_INET, ipv6: AF_INET6
                    ) else {
                        self.fail(BoringTunError.packetFlowReadFailed)
                        return
                    }
                    let af = proto.int32Value
                    let family: IPPacketFamily = af == AF_INET ? .ipv4 : .ipv6
                    // Drop malformed/torn IP envelopes before the Rust C ABI.
                    guard IPPacketEnvelope.isValid(packet, family: family) else { continue }
                    do { try self.process(codec.encapsulate(packet)) }
                    catch { self.fail(error); return }
                }
                if packets.isEmpty {
                    // Never tight-spin when packetFlow returns an empty batch.
                    self.queue.asyncAfter(deadline: .now() + .milliseconds(25)) { [weak self] in
                        guard let self, self.active,
                              self.lifecycle.matches(epoch) else { return }
                        self.readPackets()
                    }
                } else {
                    self.readPackets()
                }
            }
        }
    }

    private func finishStart(_ error: Error?) {
        startupDeadline?.cancel()
        startupDeadline = nil
        let completion = startCompletion
        startCompletion = nil
        completion?(error)
    }

    private func fail(_ error: Error) {
        guard active else { return }
        let wasStarting = startCompletion != nil
        teardown()
        if wasStarting {
            finishStart(error)
        } else {
            provider?.cancelTunnelWithError(error)
        }
    }

    private func teardown() {
        // Advance before releasing sockets/codec. Any older queued async
        // callback must not touch a subsequently started Rust session.
        _ = lifecycle.advance()
        active = false
        // Must suppress an already queued DNS callback before releasing
        // the Rust codec/UDP state. It does not cancel getaddrinfo.
        dnsCancellation?.cancel()
        dnsCancellation = nil
        tickTimer?.cancel()
        tickTimer = nil
        handshakeDeadline?.cancel()
        handshakeDeadline = nil
        startupDeadline?.cancel()
        startupDeadline = nil
        cancelPathWaitDeadline()
        udp?.stateUpdateHandler = nil
        udp?.cancel()
        udp = nil
        readingPackets = false
        receivingDatagram = false
        pendingSends = 0
        codec = nil
    }

    func stop(completion: @escaping () -> Void) {
        queue.async {
            self.teardown()
            self.finishStart(BoringTunError.stopped)
            completion()
        }
    }
}

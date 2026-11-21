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
    // Queue-confined epoch invalidates callbacks after stop/restart.
    private var lifecycle = TunnelLifecycleGeneration()
    private var udp: NWConnection?
    private var tickTimer: DispatchSourceTimer?
    private var handshakeDeadline: DispatchSourceTimer?
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
            do {
                let validated = try profile.validated()
                // Enforce inside the extension, including already-persisted
                // full profiles; never install unproven 0/0 and ::/0 routes.
                guard TunnelRouteSafetyPolicy.permitsStart(validated.routeMode) else {
                    throw AgentConfigurationError.unverifiedFullTunnel
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

                // Resolve outer UDP before installing inner routes. Brackets
                // are URLComponents formatting, not part of an IPv6 DNS name.
                let lookupHost = host.first == "[" && host.last == "]"
                    ? String(host.dropFirst().dropLast()) : host
                self.dnsResolver.resolve(host: lookupHost, callbackQueue: self.queue) { [weak self] result in
                    guard let self, self.active,
                          self.lifecycle.matches(epoch) else { return }
                    switch result {
                    case .failure:
                        self.fail(BoringTunError.initializationFailed)
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
                    self.connect(host: destination, port: port)
                }
            }
        } catch {
            fail(error)
        }
    }

    private func networkSettings(
        profile: ServerProfile, remoteHost: String
    ) throws -> NEPacketTunnelNetworkSettings {
        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: remoteHost)
        settings.mtu = NSNumber(value: 1420)

        let ipv4 = NEIPv4Settings(addresses: ["10.8.0.2"], subnetMasks: ["255.255.255.255"])
        if profile.routeMode == .split {
            guard let routes = TunnelUnderlayPolicy.splitIPv4Routes(
                includedIPv4CIDRs: RouteMode.split.allowedIPs
            ) else {
                throw AgentConfigurationError.unsafeUnderlayEndpoint
            }
            ipv4.includedRoutes = routes.map {
                NEIPv4Route(destinationAddress: $0.destinationAddress, subnetMask: $0.subnetMask)
            }
        } else {
            ipv4.includedRoutes = [NEIPv4Route.default()]
            let ipv6 = NEIPv6Settings(
                addresses: ["fd86:ea04:1111::2"], networkPrefixLengths: [128]
            )
            ipv6.includedRoutes = [NEIPv6Route.default()]
            settings.ipv6Settings = ipv6
            settings.dnsSettings = NEDNSSettings(servers: ["1.1.1.1", "2606:4700:4700::1111"])
        }
        settings.ipv4Settings = ipv4
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
    /// This is not an automatic roam or full-tunnel underlay implementation.
    private func startPathWaitDeadlineIfNeeded() {
        guard active, startCompletion == nil,
              let token = pathWait.beginWait() else { return }
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
        guard active, let udp, !receivingDatagram else { return }
        receivingDatagram = true
        let epoch = lifecycle.current
        udp.receiveMessage { [weak self] packet, _, _, error in
            self?.queue.async { [weak self] in
                guard let self, self.active,
                      self.lifecycle.matches(epoch) else { return }
                self.receivingDatagram = false
                if let error {
                    self.fail(error)
                    return
                }
                if let packet, !packet.isEmpty, let codec = self.codec {
                    // A random/malformed UDP message must not crash or
                    // disable the VPN; discard authentication failures.
                    if let action = try? codec.decapsulate(packet) {
                        do { try self.process(action) } catch { self.fail(error); return }
                    }
                    if codec.hasAuthenticatedHandshake && self.startCompletion != nil {
                        self.handshakeDeadline?.cancel()
                        self.handshakeDeadline = nil
                        self.finishStart(nil)
                        self.readPackets()
                    }
                }
                self.receiveDatagram()
            }
        }
    }

    private func process(_ action: BoringTunAction) throws {
        guard active else { throw BoringTunError.stopped }
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
            // The decrypted peer is not allowed to inject malformed frames.
            guard IPPacketEnvelope.isValid(packet, family: .ipv4) else { return }
            provider?.packetFlow.writePackets([packet], withProtocols: [NSNumber(value: AF_INET)])
        case .writeIPv6(let packet):
            guard IPPacketEnvelope.isValid(packet, family: .ipv6) else { return }
            provider?.packetFlow.writePackets([packet], withProtocols: [NSNumber(value: AF_INET6)])
        }
    }

    private func readPackets() {
        guard active, !readingPackets, let provider else { return }
        readingPackets = true
        let epoch = lifecycle.current
        provider.packetFlow.readPackets { [weak self] packets, protocols in
            self?.queue.async { [weak self] in
                guard let self, self.active,
                      self.lifecycle.matches(epoch) else { return }
                self.readingPackets = false
                if let codec = self.codec {
                    for (packet, proto) in zip(packets, protocols) {
                        let af = proto.int32Value
                        let family: IPPacketFamily
                        switch af {
                        case AF_INET: family = .ipv4
                        case AF_INET6: family = .ipv6
                        default: continue
                        }
                        // Drop malformed/torn IP envelopes before the Rust C ABI.
                        guard IPPacketEnvelope.isValid(packet, family: family) else { continue }
                        do { try self.process(codec.encapsulate(packet)) }
                        catch { self.fail(error); return }
                    }
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
        tickTimer?.cancel()
        tickTimer = nil
        handshakeDeadline?.cancel()
        handshakeDeadline = nil
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

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
    private var udp: NWConnection?
    private var tickTimer: DispatchSourceTimer?
    private var handshakeDeadline: DispatchSourceTimer?
    private var startCompletion: ((Error?) -> Void)?
    private var active = false
    private var readingPackets = false

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
            self.startCompletion = completion
            do {
                let validated = try profile.validated()
                let secret = try SharedKeychain.existingIdentity()
                let psk = try SharedKeychain.optionalPreSharedKey()
                self.codec = try BoringTunCodec(
                    privateKey: secret, serverKey: validated.publicKey, presharedKey: psk
                )
                guard let components = URLComponents(string: "udp://\(validated.endpoint)"),
                      let host = components.host, !host.isEmpty,
                      let portNumber = components.port,
                      let port = NWEndpoint.Port(rawValue: UInt16(portNumber)),
                      let provider = self.provider else {
                    throw AgentConfigurationError.invalidEndpoint
                }

                // Swift routing, not a second tunnel stack inside the Rust crate.
                let settings = self.networkSettings(profile: validated, remoteHost: host)
                provider.setTunnelNetworkSettings(settings) { [weak self] error in
                    self?.queue.async {
                        guard let self, self.active else { return }
                        if let error {
                            self.fail(error)
                            return
                        }
                        self.connect(host: NWEndpoint.Host(host), port: port)
                    }
                }
            } catch {
                self.fail(error)
            }
        }
    }

    private func networkSettings(
        profile: ServerProfile, remoteHost: String
    ) -> NEPacketTunnelNetworkSettings {
        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: remoteHost)
        settings.mtu = NSNumber(value: 1420)

        let ipv4 = NEIPv4Settings(addresses: ["10.8.0.2"], subnetMasks: ["255.255.255.255"])
        if profile.routeMode == .split {
            ipv4.includedRoutes = [
                NEIPv4Route(destinationAddress: "10.8.0.0", subnetMask: "255.255.255.0")
            ]
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

    private func connect(host: NWEndpoint.Host, port: NWEndpoint.Port) {
        guard active else { return }
        let connection = NWConnection(host: host, port: port, using: .udp)
        udp = connection
        connection.stateUpdateHandler = { [weak self] state in
            self?.queue.async { [weak self] in self?.connectionChanged(state) }
        }
        connection.start(queue: queue)

        let deadline = DispatchSource.makeTimerSource(queue: queue)
        deadline.schedule(deadline: .now() + .seconds(15))
        deadline.setEventHandler { [weak self] in
            guard let self, self.active, self.startCompletion != nil else { return }
            self.fail(BoringTunError.handshakeTimedOut)
        }
        handshakeDeadline = deadline
        deadline.resume()
    }

    private func connectionChanged(_ state: NWConnection.State) {
        guard active else { return }
        switch state {
        case .ready:
            receiveDatagram()
            if tickTimer == nil {
                let timer = DispatchSource.makeTimerSource(queue: queue)
                timer.schedule(deadline: .now() + .milliseconds(100),
                               repeating: .milliseconds(100),
                               leeway: .milliseconds(20))
                timer.setEventHandler { [weak self] in
                    guard let self, self.active, let codec = self.codec else { return }
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
        case .waiting, .preparing, .setup:
            // NWConnection may recover on interface changes; no busy retry.
            break
        @unknown default:
            fail(BoringTunError.initializationFailed)
        }
    }

    private func receiveDatagram() {
        guard active, let udp else { return }
        udp.receiveMessage { [weak self] packet, _, _, error in
            self?.queue.async { [weak self] in
                guard let self, self.active else { return }
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
            udp.send(content: datagram, completion: .contentProcessed { [weak self] error in
                guard let error else { return }
                self?.queue.async { [weak self] in self?.fail(error) }
            })
        case .writeIPv4(let packet):
            provider?.packetFlow.writePackets([packet], withProtocols: [NSNumber(value: AF_INET)])
        case .writeIPv6(let packet):
            provider?.packetFlow.writePackets([packet], withProtocols: [NSNumber(value: AF_INET6)])
        }
    }

    private func readPackets() {
        guard active, !readingPackets, let provider else { return }
        readingPackets = true
        provider.packetFlow.readPackets { [weak self] packets, protocols in
            self?.queue.async { [weak self] in
                guard let self, self.active else { return }
                self.readingPackets = false
                if let codec = self.codec {
                    for (packet, proto) in zip(packets, protocols) {
                        let af = proto.int32Value
                        guard (af == AF_INET || af == AF_INET6), !packet.isEmpty else { continue }
                        // Reject traffic with spoofed protocol/packet versions.
                        guard let firstByte = packet.first,
                              (af == AF_INET && firstByte >> 4 == 4) ||
                              (af == AF_INET6 && firstByte >> 4 == 6) else { continue }
                        do { try self.process(codec.encapsulate(packet)) }
                        catch { self.fail(error); return }
                    }
                }
                if packets.isEmpty {
                    // Never tight-spin when packetFlow returns an empty batch.
                    self.queue.asyncAfter(deadline: .now() + .milliseconds(25)) { [weak self] in
                        self?.readPackets()
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
        active = false
        tickTimer?.cancel()
        tickTimer = nil
        handshakeDeadline?.cancel()
        handshakeDeadline = nil
        udp?.stateUpdateHandler = nil
        udp?.cancel()
        udp = nil
        readingPackets = false
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

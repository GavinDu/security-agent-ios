import Foundation
import NetworkExtension
import OSLog
import WireGuardKit

// The extension runs independently of AgentApp (including while iPhone locked).
// No UI or arbitrary HTTP requests are made from this process.
final class PacketTunnelProvider: NEPacketTunnelProvider {
    private let logger = Logger(subsystem: "com.gavindu.securityagent", category: "PacketTunnel")
    private lazy var adapter = WireGuardAdapter(with: self) { _, _ in
        // Do not persist raw WireGuard logs; upstream messages can contain
        // peer endpoints and sensitive runtime configuration.
    }

    override func startTunnel(options: [String: NSObject]?,
                              completionHandler: @escaping (Error?) -> Void) {
        SharedDiagnostics.record("starting")
        do {
            guard let profile = SharedProfileStore.load() else {
                throw AgentConfigurationError.missingProfile
            }
            let config = try buildConfiguration(profile: profile)
            adapter.start(tunnelConfiguration: config) { [weak self] error in
                if let error {
                    SharedDiagnostics.record("start_failed")
                    self?.logger.error("WireGuard adapter failed to start")
                    completionHandler(error)
                } else {
                    SharedDiagnostics.record("connected")
                    self?.logger.info("WireGuard tunnel active")
                    completionHandler(nil)
                }
            }
        } catch {
            SharedDiagnostics.record("start_failed")
            logger.error("Unable to start tunnel: configuration or Keychain unavailable")
            completionHandler(error)
        }
    }

    override func stopTunnel(with reason: NEProviderStopReason,
                             completionHandler: @escaping () -> Void) {
        adapter.stop { [weak self] error in
            if error != nil {
                SharedDiagnostics.record("stop_failed")
                self?.logger.error("WireGuard adapter failed to stop")
            } else {
                SharedDiagnostics.record("stopped")
            }
            completionHandler()
        }
    }

    private func buildConfiguration(profile: ServerProfile) throws -> TunnelConfiguration {
        _ = try profile.validated()
        let secret = try SharedKeychain.existingIdentity()
        guard let privateKey = PrivateKey(rawValue: secret),
              let serverKey = PublicKey(base64Key: profile.publicKey),
              let clientIPv4 = IPAddressRange(from: AgentConstants.clientAddress),
              let clientIPv6 = IPAddressRange(from: AgentConstants.clientIPv6Address),
              let endpoint = Endpoint(from: profile.endpoint) else {
            throw AgentConfigurationError.invalidPublicKey
        }

        var client = InterfaceConfiguration(privateKey: privateKey)
        client.addresses = [clientIPv4]
        if profile.routeMode == .full {
            client.addresses.append(clientIPv6)
            if let dns = DNSServer(from: "1.1.1.1") { client.dns = [dns] }
        }
        client.mtu = 1420

        var peer = PeerConfiguration(publicKey: serverKey)
        peer.endpoint = endpoint
        peer.allowedIPs = profile.routeMode.allowedIPs.compactMap(IPAddressRange.init(from:))
        peer.persistentKeepAlive = 25

        if let psk = try SharedKeychain.optionalPreSharedKey() {
            guard let matchingPSK = PreSharedKey(rawValue: psk) else {
                throw SharedKeychain.KeychainError.invalidSecret
            }
            peer.preSharedKey = matchingPSK
        }
        return TunnelConfiguration(name: "Security Agent", interface: client, peers: [peer])
    }
}

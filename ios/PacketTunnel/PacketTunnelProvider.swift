import Foundation
import NetworkExtension
import OSLog

// All WireGuard cryptography runs inside pinned Rust BoringTun (staticlib).
// The Swift PacketTunnel owns Apple VPN settings, UDP I/O and lifecycle.
final class PacketTunnelProvider: NEPacketTunnelProvider {
    private let logger = Logger(subsystem: "com.gavindu.securityagent", category: "PacketTunnel")
    private var engine: BoringTunTransport?

    override func startTunnel(options: [String: NSObject]?,
                              completionHandler: @escaping (Error?) -> Void) {
        SharedDiagnostics.record("starting")
        guard let profile = SharedProfileStore.load() else {
            SharedDiagnostics.record("start_failed")
            completionHandler(AgentConfigurationError.missingProfile)
            return
        }
        let transport = BoringTunTransport(provider: self)
        engine = transport
        transport.start(profile: profile) { [weak self] error in
            if let error {
                SharedDiagnostics.record("start_failed")
                self?.logger.error("BoringTun tunnel start failed")
                self?.engine = nil
                completionHandler(error)
            } else {
                // Unlike a socket-ready signal, the transport only reports
                // success after verifying the WireGuard handshake.
                SharedDiagnostics.record("connected")
                self?.logger.info("Rust WireGuard peer handshake complete")
                completionHandler(nil)
            }
        }
    }

    override func stopTunnel(with reason: NEProviderStopReason,
                             completionHandler: @escaping () -> Void) {
        guard let engine else {
            SharedDiagnostics.record("stopped")
            completionHandler()
            return
        }
        engine.stop { [weak self] in
            self?.engine = nil
            SharedDiagnostics.record("stopped")
            completionHandler()
        }
    }
}

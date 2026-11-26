import Foundation
import NetworkExtension
import OSLog

// All WireGuard cryptography runs inside pinned Rust BoringTun (staticlib).
// All provider engine ownership and callback completion transitions are
// serialized on lifecycleQueue, separately from BoringTunTransport's
// queue-confined Rust C ABI.
final class PacketTunnelProvider: NEPacketTunnelProvider {
    private let logger = Logger(subsystem: "com.gavindu.securityagent", category: "PacketTunnel")
    private let lifecycleQueue = DispatchQueue(label: "com.gavindu.securityagent.provider-lifecycle")
    private var ownership = PacketTunnelProviderOwnership<BoringTunTransport>()

    override func startTunnel(options: [String: NSObject]?,
                              completionHandler: @escaping (Error?) -> Void) {
        let completion = PacketTunnelOneShot<Error?>(completionHandler)
        lifecycleQueue.async {
            guard self.ownership.beginStart(completion) else {
                completion.call(BoringTunError.initializationFailed)
                return
            }
            SharedDiagnostics.record("starting")
            guard SharedPreferenceWriteJournal.current.state == .clear else {
                self.ownership.failPreparation()
                SharedDiagnostics.record("start_failed")
                completion.call(AgentConfigurationError.preferenceRecoveryRequired)
                return
            }
            guard let profile = SharedProfileStore.load() else {
                self.ownership.failPreparation()
                SharedDiagnostics.record("start_failed")
                completion.call(AgentConfigurationError.missingProfile)
                return
            }
            // Do not trust a stale App Group profile after a partial native
            // preferences save. Reject v1/missing/mismatched metadata before
            // constructing the Rust engine or installing VPN routes.
            guard let native = self.protocolConfiguration as? NETunnelProviderProtocol,
                  native.providerBundleIdentifier == AgentConstants.tunnelBundleID,
                  native.serverAddress == profile.endpoint,
                  NativeProfileBindingPolicy.allowsStart(
                    metadata: native.providerConfiguration,
                    profileDigest: try? profile.publicProfileDigest()
                  ) else {
                self.ownership.failPreparation()
                SharedDiagnostics.record("start_failed")
                completion.call(AgentConfigurationError.nativeProfileMismatch)
                return
            }
            let transport = BoringTunTransport(provider: self)
            self.ownership.installEngine(transport)
            transport.start(profile: profile) { [weak self] error in
                guard let self else {
                    completion.call(BoringTunError.stopped)
                    return
                }
                self.lifecycleQueue.async {
                    // An old callback must never clear the next engine.
                    guard self.ownership.finishStart(for: transport, success: error == nil) else {
                        // Obsolete completion is not evidence of the current attempt.
                        completion.call(BoringTunError.stopped)
                        return
                    }
                    if let error {
                        // Typed finite classification only, after the current-engine guard.
                        // Do not log raw NSError text or hostnames. One event per failure.
                        if let dns = error as? UnderlayDNSResolutionError {
                            SharedDiagnostics.record(dns.diagnosticEventCode)
                        } else if let configuration = error as? AgentConfigurationError,
                                  case .unsafeUnderlayEndpoint = configuration {
                            SharedDiagnostics.record("unsafe_underlay_rejected")
                        } else {
                            SharedDiagnostics.record("start_failed")
                        }
                        self.logger.error("BoringTun tunnel start failed")
                        completion.call(error)
                    } else {
                        // Success means a verified WireGuard handshake,
                        // never merely an open UDP socket.
                        SharedDiagnostics.record("connected")
                        self.logger.info("Rust WireGuard peer handshake complete")
                        completion.call(nil)
                    }
                }
            }
        }
    }

    override func stopTunnel(with reason: NEProviderStopReason,
                             completionHandler: @escaping () -> Void) {
        lifecycleQueue.async {
            guard self.ownership.beginStop(completionHandler) else {
                // A second stop during teardown only queues its completion.
                if self.ownership.phase == .idle { self.finishStopWaiters() }
                return
            }
            guard let transport = self.ownership.engine else {
                guard self.ownership.finishStop(for: nil) else { return }
                self.finishStopWaiters()
                return
            }
            transport.stop {
                self.lifecycleQueue.async {
                    // An obsolete or duplicated transport stop callback must
                    // never complete waiters for a newer engine's teardown.
                    guard self.ownership.finishStop(for: transport) else { return }
                    self.finishStopWaiters()
                }
            }
        }
    }

    private func finishStopWaiters() {
        // The provider cannot release callbacks early; collect once and
        // invoke outside the mutable waiter array.
        let callbacks = ownership.takeStopCallbacks()
        // Stop must also complete a still-pending start, even when a
        // transport never delivers its start callback after teardown.
        callbacks.start?.call(BoringTunError.stopped)
        SharedDiagnostics.record("stopped")
        for completion in callbacks.stops { completion() }
    }
}

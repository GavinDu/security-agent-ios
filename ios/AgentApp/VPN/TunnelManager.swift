import Foundation
import NetworkExtension
import SwiftUI

final class TunnelManager: NSObject, ObservableObject {
    @Published private(set) var status: NEVPNStatus = .invalid
    @Published private(set) var profile: ServerProfile? = SharedProfileStore.load()
    @Published var errorMessage: String?
    @Published var showSettings = false
    private var manager: NETunnelProviderManager?
    private let profileSave = ProfileSaveSequencer()

    override init() {
        super.init()
        NotificationCenter.default.addObserver(
            self,
            selector: #selector(vpnStatusChanged),
            name: .NEVPNStatusDidChange,
            object: nil
        )
        reload()
    }

    deinit { NotificationCenter.default.removeObserver(self) }

    @objc private func vpnStatusChanged(_ notification: Notification) {
        DispatchQueue.main.async { self.status = self.manager?.connection.status ?? .invalid }
    }

    func reload() {
        NETunnelProviderManager.loadAllFromPreferences { managers, error in
            DispatchQueue.main.async {
                // Never overwrite an in-flight native preference transaction
                // with an older asynchronous loadAllFromPreferences result.
                guard !self.profileSave.isBusy else { return }
                if let error { self.errorMessage = error.localizedDescription }
                self.manager = managers?.first(where: {
                    ($0.protocolConfiguration as? NETunnelProviderProtocol)?
                        .providerBundleIdentifier == AgentConstants.tunnelBundleID
                })
                self.status = self.manager?.connection.status ?? .invalid
                self.profile = SharedProfileStore.load()
            }
        }
    }

    func save(_ candidate: ServerProfile, connectAfterSave: Bool = false) {
        // The UI publishes only profiles accepted and reloaded by the system.
        guard !profileSave.isBusy else {
            errorMessage = ProfileSaveSequencer.TransactionError.busy.localizedDescription
            return
        }
        let validated: ServerProfile
        do { validated = try candidate.validated() }
        catch { errorMessage = error.localizedDescription; return }

        let selected = manager ?? NETunnelProviderManager()
        let configuration = (selected.protocolConfiguration as? NETunnelProviderProtocol)
            ?? NETunnelProviderProtocol()
        configuration.providerBundleIdentifier = AgentConstants.tunnelBundleID
        configuration.serverAddress = validated.endpoint
        // No private key, PSK or decrypted traffic in the system profile.
        configuration.providerConfiguration = ["profileVersion": 1]
        selected.protocolConfiguration = configuration
        selected.localizedDescription = "Security Agent VPN"
        selected.isEnabled = true
        selected.onDemandRules = validated.onDemand ? [NEOnDemandRuleConnect()] : []
        selected.isOnDemandEnabled = validated.onDemand

        profileSave.run(
            saveNative: { callback in selected.saveToPreferences(completionHandler: callback) },
            reloadNative: { callback in selected.loadFromPreferences(completionHandler: callback) },
            commitPublicProfile: { try SharedProfileStore.save(validated) },
            completed: { [weak self] result in
                guard let self else { return }
                switch result {
                case .success:
                    self.manager = selected
                    self.profile = validated
                    self.status = selected.connection.status
                    self.errorMessage = nil
                    if connectAfterSave { self.connect() }
                case .failure(let error):
                    // No new public profile was committed on denial or reload
                    // failure. Re-read the native manager; do not delete a
                    // previous owner-configured VPN profile as 'rollback'.
                    self.errorMessage = error.localizedDescription
                    self.reload()
                }
            }
        )
    }

    func connect() {
        guard !profileSave.isBusy else {
            errorMessage = "Finish saving the VPN configuration before connecting."
            return
        }
        guard profile != nil else {
            errorMessage = AgentConfigurationError.missingProfile.localizedDescription
            return
        }
        guard let manager else {
            errorMessage = "Install the VPN configuration before connecting."
            return
        }
        do { try manager.connection.startVPNTunnel() }
        catch { errorMessage = error.localizedDescription }
    }

    func disconnect() { manager?.connection.stopVPNTunnel() }

    func changeRoute(to mode: RouteMode) {
        guard var updated = profile, updated.routeMode != mode else { return }
        // Mode transitions require a full tunnel restart. Do not reconnect
        // until the previous tunnel has actually stopped.
        disconnect()
        updated.routeMode = mode
        save(updated)
    }

    func setOnDemand(_ enabled: Bool) {
        guard var updated = profile else { return }
        updated.onDemand = enabled
        save(updated)
    }

    var statusDescription: String {
        switch status {
        case .connected: return "Connected"
        case .connecting: return "Connecting"
        case .reasserting: return "Reconnecting"
        case .disconnecting: return "Disconnecting"
        case .disconnected: return "Disconnected"
        case .invalid: return "Not configured"
        @unknown default: return "Unknown"
        }
    }
}

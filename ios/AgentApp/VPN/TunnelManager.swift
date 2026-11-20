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
    private var legacyFullStopRequested = false
    private var legacyOnDemandDisableAttempted = false
    private var legacyOnDemandDisableInFlight = false

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
        DispatchQueue.main.async {
            self.status = self.manager?.connection.status ?? .invalid
            self.remediateLegacyFullTunnel()
        }
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
                self.remediateLegacyFullTunnel()
            }
        }
    }

    /// Stop any inherited full-tunnel session and disable old on-demand rules.
    /// The extension is still the final boundary for new VPN starts.
    private func remediateLegacyFullTunnel() {
        guard let profile, let manager else { return }
        let status = manager.connection.status
        let active = status == .connected || status == .connecting || status == .reasserting
        let action = LegacyFullTunnelRecovery.assess(
            isFullMode: profile.routeMode == .full,
            isActive: active,
            isOnDemandEnabled: manager.isOnDemandEnabled
        )
        if !action.stopActiveSession {
            legacyFullStopRequested = false
        } else if !legacyFullStopRequested {
            legacyFullStopRequested = true
            manager.connection.stopVPNTunnel()
        }
        guard action.blockNewConnection else { return }
        if errorMessage == nil {
            errorMessage = AgentConfigurationError.unverifiedFullTunnel.localizedDescription
        }
        // Single attempt per app lifecycle. A denied preference write is
        // surfaced to the user; never retry indefinitely in a VPN callback.
        guard action.disableOnDemand, !legacyOnDemandDisableAttempted,
              !legacyOnDemandDisableInFlight, !profileSave.isBusy else { return }
        legacyOnDemandDisableAttempted = true
        legacyOnDemandDisableInFlight = true
        manager.isOnDemandEnabled = false
        manager.onDemandRules = []
        manager.saveToPreferences { [weak self] error in
            DispatchQueue.main.async {
                guard let self else { return }
                self.legacyOnDemandDisableInFlight = false
                if let error {
                    self.errorMessage = "Could not disable legacy VPN auto-connect: " +
                        error.localizedDescription
                } else {
                    // Re-read system state; do not replace the public
                    // profile or claim that an active tunnel was stopped.
                    self.reload()
                }
            }
        }
    }

    func save(_ candidate: ServerProfile, connectAfterSave: Bool = false) {
        guard !legacyOnDemandDisableInFlight else {
            errorMessage = "Finish disabling legacy VPN auto-connect first."
            return
        }
        // The UI publishes only profiles accepted and reloaded by the system.
        guard !profileSave.isBusy else {
            errorMessage = ProfileSaveSequencer.TransactionError.busy.localizedDescription
            return
        }
        let validated: ServerProfile
        do { validated = try candidate.validated() }
        catch { errorMessage = error.localizedDescription; return }
        guard TunnelRouteSafetyPolicy.permitsStart(validated.routeMode) else {
            errorMessage = AgentConfigurationError.unverifiedFullTunnel.localizedDescription
            return
        }

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
        guard !legacyOnDemandDisableInFlight else {
            errorMessage = "Finish disabling legacy VPN auto-connect first."
            return
        }
        guard !profileSave.isBusy else {
            errorMessage = "Finish saving the VPN configuration before connecting."
            return
        }
        guard let profile else {
            errorMessage = AgentConfigurationError.missingProfile.localizedDescription
            return
        }
        guard TunnelRouteSafetyPolicy.permitsStart(profile.routeMode) else {
            errorMessage = AgentConfigurationError.unverifiedFullTunnel.localizedDescription
            remediateLegacyFullTunnel()
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
        guard TunnelRouteSafetyPolicy.permitsStart(mode) else {
            errorMessage = AgentConfigurationError.unverifiedFullTunnel.localizedDescription
            return
        }
        // Mode transitions require a full tunnel restart. Do not reconnect
        // until the previous tunnel has actually stopped.
        disconnect()
        updated.routeMode = mode
        save(updated)
    }

    func setOnDemand(_ enabled: Bool) {
        guard var updated = profile else { return }
        if enabled && !TunnelRouteSafetyPolicy.permitsStart(updated.routeMode) {
            errorMessage = AgentConfigurationError.unverifiedFullTunnel.localizedDescription
            remediateLegacyFullTunnel()
            return
        }
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

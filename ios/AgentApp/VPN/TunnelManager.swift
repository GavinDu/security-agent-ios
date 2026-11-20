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
    private var preferenceReloadGate = NativePreferenceReloadGate()
    // Initial native inventory must finish before a profile may be created.
    private var nativeInventoryLoading = true
    private var duplicateNativeManagers = false
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
        // Keep the request identity and all native manager/UI mutations on main.
        // An older loadAll callback must not replace a manager committed by a
        // newer reload or a successful save transaction.
        if !Thread.isMainThread {
            DispatchQueue.main.async { [weak self] in self?.reload() }
            return
        }
        guard !profileSave.isBusy && !legacyOnDemandDisableInFlight else { return }
        let loadToken = preferenceReloadGate.begin()
        nativeInventoryLoading = true
        NETunnelProviderManager.loadAllFromPreferences { [weak self] managers, error in
            DispatchQueue.main.async { [weak self] in
                guard let self else { return }
                switch self.preferenceReloadGate.disposition(
                    for: loadToken,
                    writeInFlight: self.profileSave.isBusy || self.legacyOnDemandDisableInFlight,
                    loadSucceeded: error == nil && managers != nil
                ) {
                case .discard:
                    // An old generation must not clear a newer in-flight load.
                    return
                case .reportFailure:
                    self.nativeInventoryLoading = false
                    // Preserve the previously confirmed manager on OS errors.
                    self.errorMessage = error?.localizedDescription ??
                        "Could not reload VPN preferences."
                    return
                case .publish:
                    self.nativeInventoryLoading = false
                }

                let inventory = NativeVPNManagerInventory.select(
                    from: managers ?? [],
                    matching: {
                        ($0.protocolConfiguration as? NETunnelProviderProtocol)?
                            .providerBundleIdentifier == AgentConstants.tunnelBundleID
                    }
                )
                switch inventory {
                case .duplicate:
                    // Never guess which system VPN profile is authoritative.
                    self.duplicateNativeManagers = true
                    self.manager = nil
                    self.status = .invalid
                    self.errorMessage = "Multiple Security Agent VPN profiles found. " +
                        "Remove duplicate entries in iOS Settings, then return to the app."
                    return
                case .none:
                    self.manager = nil
                case .one(let selected):
                    self.manager = selected
                }
                let hadDuplicates = self.duplicateNativeManagers
                self.duplicateNativeManagers = false
                if hadDuplicates { self.errorMessage = nil }
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
        // A previous loadAll callback cannot overwrite the native manager
        // while we mutate on-demand preferences.
        preferenceReloadGate.invalidate()
        nativeInventoryLoading = false
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
                }
                // In-memory manager fields were modified before the native
                // write. Reload on denial as well as success so a later
                // route edit never trusts the optimistic on-demand value.
                self.reload()
            }
        }
    }

    func save(_ candidate: ServerProfile, connectAfterSave: Bool = false) {
        // Native manager mutations and reload generations are main confined.
        // ProfileSaveSequencer marshals its own work, but the manager setup
        // performed before run() must also be serialized on the main queue.
        if !Thread.isMainThread {
            DispatchQueue.main.async { [weak self] in
                self?.save(candidate, connectAfterSave: connectAfterSave)
            }
            return
        }
        guard !legacyOnDemandDisableInFlight else {
            errorMessage = "Finish disabling legacy VPN auto-connect first."
            return
        }
        guard !nativeInventoryLoading && !duplicateNativeManagers else {
            errorMessage = "Wait for VPN preferences to load, or remove duplicate " +
                "Security Agent VPN entries in iOS Settings before saving."
            return
        }
        // The UI publishes only profiles accepted and reloaded by the system.
        guard !profileSave.isBusy else {
            errorMessage = ProfileSaveSequencer.TransactionError.busy.localizedDescription
            return
        }
        let validated: ServerProfile
        let bindingDigest: String
        do {
            validated = try candidate.validated()
            bindingDigest = try validated.publicProfileDigest()
        } catch {
            errorMessage = error.localizedDescription
            return
        }
        guard TunnelRouteSafetyPolicy.permitsStart(validated.routeMode) else {
            errorMessage = AgentConfigurationError.unverifiedFullTunnel.localizedDescription
            return
        }

        // Invalidate pending loadAll results before changing native settings.
        preferenceReloadGate.invalidate()
        let selected = manager ?? NETunnelProviderManager()
        let configuration = (selected.protocolConfiguration as? NETunnelProviderProtocol)
            ?? NETunnelProviderProtocol()
        configuration.providerBundleIdentifier = AgentConstants.tunnelBundleID
        configuration.serverAddress = validated.endpoint
        // Only the versioned SHA-256 of validated public metadata; never
        // include the private WireGuard key or preshared key here.
        configuration.providerConfiguration =
            NativeProfileBindingPolicy.metadata(for: bindingDigest)
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
        if !Thread.isMainThread {
            DispatchQueue.main.async { [weak self] in self?.connect() }
            return
        }
        guard !nativeInventoryLoading && !duplicateNativeManagers else {
            errorMessage = "Wait for VPN preferences to load, or remove duplicate " +
                "Security Agent VPN entries in iOS Settings before connecting."
            return
        }
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
        // App-side early rejection; the extension independently validates
        // fresh system metadata before any Rust engine or routes are created.
        guard let native = manager.protocolConfiguration as? NETunnelProviderProtocol,
              native.providerBundleIdentifier == AgentConstants.tunnelBundleID,
              native.serverAddress == profile.endpoint,
              NativeProfileBindingPolicy.allowsStart(
                metadata: native.providerConfiguration,
                profileDigest: try? profile.publicProfileDigest()
              ) else {
            errorMessage = AgentConfigurationError.nativeProfileMismatch.localizedDescription
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
        // Stop is asynchronous: do not save route preferences until native
        // NetworkExtension confirms the old session is disconnected. Never
        // let OS on-demand reconnect the old route during preference changes.
        let nativeStatus = manager?.connection.status ?? .invalid
        let disconnected = nativeStatus == .disconnected || nativeStatus == .invalid
        guard RouteEditSafetyPolicy.permitsEdit(
            nativeDisconnected: disconnected,
            nativeOnDemandEnabled: manager?.isOnDemandEnabled ?? false,
            saveInFlight: profileSave.isBusy || legacyOnDemandDisableInFlight
        ) else {
            errorMessage = "Turn off Connect on demand, disconnect the VPN, " +
                "and wait for Disconnected before changing routing mode."
            return
        }
        updated.routeMode = mode
        // Recovering from an old full-route profile must never silently
        // recreate its on-demand connection policy during this save.
        updated.onDemand = false
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

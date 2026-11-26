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
    // A failed native preference read must never reopen writes/connections.
    // Keep this state on main with NativePreferenceReloadGate generations.
    // Publish each value-type trust transition. Otherwise SwiftUI could keep
    // a previously mounted WKWebView alive after a native inventory load or
    // preference write revoked verification without changing VPN status.
    @Published private var nativeInventoryTrust = NativeVPNInventoryTrust()
    private var legacyFullStopRequested = false
    private weak var legacyStopManager: NETunnelProviderManager?
    private var legacyOnDemandDisableAttempted = false
    private var legacyOnDemandDisableInFlight = false
    private var legacyDisableToken: UUID?
    @Published private var routeStop = RouteStopTransaction()
    private struct PendingRoute {
        let token: UUID
        let manager: NETunnelProviderManager
        let original: ServerProfile
        let candidate: ServerProfile
    }
    private var pendingRoute: PendingRoute?
    var isChangingRoute: Bool { routeStop.isPending }

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
            self.advanceRouteChange()
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
        if profileSave.isAwaitingNativeCompletion {
            errorMessage = "VPN preferences are awaiting a native completion. Do not reconnect or retry yet."
            return
        }
        guard !profileSave.isBusy && !legacyOnDemandDisableInFlight else { return }
        cancelRouteChange("VPN preferences are being reloaded. Choose the route again after verification.")
        let loadToken = preferenceReloadGate.begin()
        nativeInventoryTrust.beginLoad()
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
                    self.nativeInventoryTrust.didFailLoad()
                    // Preserve the previously confirmed manager on OS errors,
                    // but forbid writing through it until a successful reload.
                    self.errorMessage = error?.localizedDescription ??
                        "Could not reload VPN preferences."
                    return
                case .publish:
                    // Only a subsequent unique/empty inventory decision may
                    // authorize a new save or connect.
                    break
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
                    self.nativeInventoryTrust.didLoadDuplicateInventory()
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
                // A previous failed/ambiguous load is recovered only by this
                // current-generation, successful native inventory read.
                self.nativeInventoryTrust.didLoadUniqueInventory()
                self.status = self.manager?.connection.status ?? .invalid
                self.profile = SharedProfileStore.load()
                self.remediateLegacyFullTunnel()
            }
        }
    }

    /// Stop inherited full-mode OR orphaned app-owned native sessions and
    /// disable on-demand rules. New PacketTunnel starts remain fail-closed.
    private func remediateLegacyFullTunnel() {
        // This manager was selected only after matching our provider bundle ID.
        // A missing/unreadable App Group profile cannot certify a safe split
        // route; do not leave a potentially old active tunnel running.
        guard let manager else { return }
        // The explicit route transaction owns its stop request until it finishes.
        guard !routeStop.isPending else { return }
        let status = manager.connection.status
        let active = status == .connected || status == .connecting || status == .reasserting
        // A loaded public profile can be stale relative to native system
        // preferences. Only an exact v2 binding certifies a split route;
        // absent or mismatched native metadata is untrusted like missing
        // App Group bytes. Do not assume a running old extension restarted.
        var verifiedRouteIsFull: Bool?
        if let profile, SharedProfileStore.load() == profile,
           let native = manager.protocolConfiguration as? NETunnelProviderProtocol,
           native.providerBundleIdentifier == AgentConstants.tunnelBundleID,
           native.serverAddress == profile.endpoint,
           NativeProfileBindingPolicy.allowsStart(
            metadata: native.providerConfiguration,
            profileDigest: try? profile.publicProfileDigest()
           ) {
            verifiedRouteIsFull = profile.routeMode == .full
        }
        let action = LegacyFullTunnelRecovery.assess(
            isFullMode: verifiedRouteIsFull,
            isActive: active,
            isOnDemandEnabled: manager.isOnDemandEnabled
        )
        if !action.stopActiveSession {
            legacyFullStopRequested = false
            legacyStopManager = nil
        } else if !legacyFullStopRequested || legacyStopManager !== manager {
            legacyFullStopRequested = true
            legacyStopManager = manager
            manager.connection.stopVPNTunnel()
        }
        guard action.blockNewConnection else { return }
        if errorMessage == nil {
            errorMessage = verifiedRouteIsFull == nil
                ? "Security Agent VPN pairing data is missing or invalid. " +
                  "Disconnect, disable Connect on demand and re-pair your Mac."
                : AgentConfigurationError.unverifiedFullTunnel.localizedDescription
        }
        // Single attempt per app lifecycle. A denied preference write is
        // surfaced to the user; never retry indefinitely in a VPN callback.
        if action.disableOnDemand && legacyOnDemandDisableAttempted && !legacyOnDemandDisableInFlight {
            errorMessage = "Legacy VPN auto-connect remains enabled. Disable it in iOS Settings, then reload."
            return
        }
        guard action.disableOnDemand, !legacyOnDemandDisableAttempted,
              !legacyOnDemandDisableInFlight, !profileSave.isBusy,
              nativeInventoryTrust.permitsMutation else { return }
        // A previous loadAll callback cannot overwrite the native manager
        // while we mutate on-demand preferences.
        preferenceReloadGate.invalidate()
        nativeInventoryTrust.beginWrite()
        legacyOnDemandDisableAttempted = true
        legacyOnDemandDisableInFlight = true
        let disableToken = UUID()
        legacyDisableToken = disableToken
        manager.isOnDemandEnabled = false
        manager.onDemandRules = []
        // Report a hung callback without reopening mutation trust. The OS
        // preference write cannot be cancelled, so a deadline is NOT proof
        // that it is safe to start a different write or connect.
        DispatchQueue.main.asyncAfter(deadline: .now() + 30) { [weak self] in
            guard let self, self.legacyDisableToken == disableToken else { return }
            self.errorMessage = "Legacy VPN auto-connect update has not completed. " +
                "Do not reconnect; check iOS VPN Settings."
        }
        manager.saveToPreferences { [weak self] error in
            DispatchQueue.main.async {
                guard let self, self.legacyDisableToken == disableToken,
                      self.manager === manager else { return }
                self.legacyDisableToken = nil
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
        guard !routeStop.isPending else {
            errorMessage = "Wait for the route change to finish."
            return
        }
        guard !legacyOnDemandDisableInFlight else {
            errorMessage = "Finish disabling legacy VPN auto-connect first."
            return
        }
        guard nativeInventoryTrust.permitsMutation else {
            errorMessage = "VPN preferences are not verified. Retry loading VPN " +
                "preferences, or remove duplicate Security Agent entries in iOS Settings."
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
        // Pairing and on-demand changes also enter this generic save method,
        // not just the route editor. Never change the system VPN profile while
        // an old Rust BoringTun session may still own its peer or routes.
        let nativeStatus = manager?.connection.status ?? .invalid
        let nativeDisconnected = nativeStatus == .disconnected || (manager == nil && nativeStatus == .invalid)
        let changesPeerOrRoutes = profile.map { old in
            old.publicKey != validated.publicKey ||
            old.endpoint != validated.endpoint ||
            old.routeMode != validated.routeMode
        } ?? true
        guard ProfileSaveSafetyPolicy.permitsSave(
            hasInstalledManager: manager != nil,
            nativeDisconnected: nativeDisconnected,
            nativeOnDemandEnabled: manager?.isOnDemandEnabled ?? false,
            changesPeerOrRoutes: changesPeerOrRoutes,
            candidateOnDemand: validated.onDemand
        ) else {
            // Leave existing native preferences, App Group profile, and running
            // PacketTunnel untouched; require explicit owner action.
            errorMessage = "Disconnect VPN and wait for Disconnected before " +
                "saving a new pairing. If Connect on demand is enabled, " +
                "turn it off first without changing the peer or routes."
            return
        }

        // Invalidate prior inventory trust and pending loadAll callbacks
        // before changing any native settings.
        preferenceReloadGate.invalidate()
        nativeInventoryTrust.beginWrite()
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
            reloadNative: { callback in
                selected.loadFromPreferences { error in
                    guard error == nil else {
                        callback(error)
                        return
                    }
                    // NetworkExtension callbacks may be delivered off-main.
                    // Verify the freshly reloaded native state before the
                    // sequencer may commit the App Group public profile.
                    DispatchQueue.main.async {
                        let native = selected.protocolConfiguration as? NETunnelProviderProtocol
                        let snapshot = NativePreferenceCommitSnapshot(
                            providerBundleIdentifier: native?.providerBundleIdentifier,
                            serverAddress: native?.serverAddress,
                            metadata: native?.providerConfiguration,
                            isEnabled: selected.isEnabled,
                            isOnDemandEnabled: selected.isOnDemandEnabled,
                            onDemandRuleCount: selected.onDemandRules?.count ?? 0,
                            onDemandUsesConnectRule:
                                selected.onDemandRules?.first is NEOnDemandRuleConnect
                        )
                        guard NativePreferenceCommitVerifier.matches(
                            snapshot,
                            expectedBundleID: AgentConstants.tunnelBundleID,
                            expectedServerAddress: validated.endpoint,
                            expectedProfileDigest: bindingDigest,
                            expectedOnDemand: validated.onDemand
                        ) else {
                            callback(AgentConfigurationError.nativeProfileMismatch)
                            return
                        }
                        callback(nil)
                    }
                }
            },
            commitPublicProfile: { try SharedProfileStore.save(validated) },
            nativeSettledAfterTimeout: { [weak self] in
                // Never trust a load made before the late OS operation settles.
                self?.reload()
            },
            completed: { [weak self] result in
                guard let self else { return }
                switch result {
                case .success:
                    self.nativeInventoryTrust.didCommitVerifiedWrite()
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
                    if !self.profileSave.isAwaitingNativeCompletion {
                        self.reload()
                    }
                }
            }
        )
    }

    func connect() {
        if !Thread.isMainThread {
            DispatchQueue.main.async { [weak self] in self?.connect() }
            return
        }
        guard nativeInventoryTrust.permitsMutation else {
            errorMessage = "VPN preferences are not verified. Retry loading VPN " +
                "preferences, or remove duplicate Security Agent entries in iOS Settings."
            return
        }
        guard !routeStop.isPending else {
            errorMessage = "Wait for the route change to finish."
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

    func disconnect() {
        if !Thread.isMainThread {
            DispatchQueue.main.async { [weak self] in self?.disconnect() }
            return
        }
        cancelRouteChange("Route change cancelled. Wait for the VPN to disconnect.")
        manager?.connection.stopVPNTunnel()
    }

    func changeRoute(to mode: RouteMode) {
        // All reads and mutations of published profile/native manager state
        // must share save()/connect() main-queue confinement.
        if !Thread.isMainThread {
            DispatchQueue.main.async { [weak self] in self?.changeRoute(to: mode) }
            return
        }
        guard var updated = profile, updated.routeMode != mode else { return }
        guard TunnelRouteSafetyPolicy.permitsStart(mode) else {
            errorMessage = AgentConfigurationError.unverifiedFullTunnel.localizedDescription
            return
        }
        guard nativeInventoryTrust.permitsMutation, !routeStop.isPending,
              !profileSave.isBusy, !legacyOnDemandDisableInFlight else {
            errorMessage = "Finish or reload the current VPN configuration before changing routes."
            return
        }
        // On-demand must be disabled and verified first; otherwise the OS
        // may reconnect the old routes before this transaction can commit.
        let nativeStatus = manager?.connection.status ?? .invalid
        let disconnected = nativeStatus == .disconnected || (manager == nil && nativeStatus == .invalid)
        guard !(manager?.isOnDemandEnabled ?? false) else {
            errorMessage = "Turn off Connect on demand before changing routing mode."
            return
        }
        let original = updated
        guard SharedProfileStore.load() == original else {
            errorMessage = "Saved pairing changed. Reload preferences before changing routes."
            return
        }
        updated.routeMode = mode
        updated.onDemand = false
        do { updated = try updated.validated() }
        catch { errorMessage = error.localizedDescription; return }

        if RouteEditSafetyPolicy.permitsEdit(
            nativeDisconnected: disconnected,
            nativeOnDemandEnabled: manager?.isOnDemandEnabled ?? false,
            saveInFlight: profileSave.isBusy || legacyOnDemandDisableInFlight
        ) {
            save(updated)
            return
        }
        guard let manager,
              nativeStatus == .connected || nativeStatus == .connecting ||
              nativeStatus == .reasserting || nativeStatus == .disconnecting,
              let token = routeStop.begin() else {
            errorMessage = "VPN state is unavailable. Reload preferences before changing routes."
            return
        }
        pendingRoute = PendingRoute(token: token, manager: manager,
                                    original: original, candidate: updated)
        // Mode selection is explicit consent to stop, never to reconnect.
        // An inherited recovery may have already requested the same stop.
        if nativeStatus != .disconnecting &&
            (!legacyFullStopRequested || legacyStopManager !== manager) {
            manager.connection.stopVPNTunnel()
        }
        DispatchQueue.main.asyncAfter(deadline: .now() + 30) { [weak self] in
            guard let self, self.routeStop.cancel(token) else { return }
            self.pendingRoute = nil
            self.errorMessage = "VPN did not disconnect in time. Reload preferences and retry."
            self.remediateLegacyFullTunnel()
        }
        // Also sample immediately: a stop can complete before a notification.
        advanceRouteChange()
    }

    private func advanceRouteChange() {
        guard let pending = pendingRoute else { return }
        let nativeStatus = pending.manager.connection.status
        let knownStatus = nativeStatus == .disconnected || nativeStatus == .disconnecting ||
            nativeStatus == .connected || nativeStatus == .connecting || nativeStatus == .reasserting
        let valid = manager === pending.manager && profile == pending.original &&
            SharedProfileStore.load() == pending.original &&
            nativeInventoryTrust.permitsMutation && !pending.manager.isOnDemandEnabled &&
            !profileSave.isBusy && !legacyOnDemandDisableInFlight && knownStatus &&
            TunnelRouteSafetyPolicy.permitsStart(pending.candidate.routeMode)
        switch routeStop.observe(pending.token, disconnected: nativeStatus == .disconnected,
                                 contextValid: valid) {
        case .ignored, .waiting:
            return
        case .cancelled:
            pendingRoute = nil
            errorMessage = "VPN state changed before the route could be saved. Reload preferences and retry."
        case .commit:
            pendingRoute = nil
            // save() repeats native state and inventory checks, then verifies
            // readback before publishing. Never reconnect implicitly.
            save(pending.candidate)
        }
    }

    private func cancelRouteChange(_ message: String) {
        guard let pending = pendingRoute, routeStop.cancel(pending.token) else { return }
        pendingRoute = nil
        errorMessage = message
    }

    func setOnDemand(_ enabled: Bool) {
        if !Thread.isMainThread {
            DispatchQueue.main.async { [weak self] in self?.setOnDemand(enabled) }
            return
        }
        guard var updated = profile else { return }
        if enabled && !TunnelRouteSafetyPolicy.permitsStart(updated.routeMode) {
            errorMessage = AgentConfigurationError.unverifiedFullTunnel.localizedDescription
            remediateLegacyFullTunnel()
            return
        }
        updated.onDemand = enabled
        save(updated)
    }

    /// The UI must never construct VPN-private WebKit based solely on the
    /// system's .connected flag: a previously running or externally edited
    /// NETunnelProviderManager can be connected with stale App Group data.
    /// This is an app-side gate; PacketTunnel start performs its own binding
    /// validation before allocating the Rust BoringTun engine.
    var canShowPrivateChat: Bool {
        let native = manager?.protocolConfiguration as? NETunnelProviderProtocol
        let isValidSplitProfile: Bool
        let matchesNative: Bool
        if let profile, let native {
            isValidSplitProfile = profile.routeMode == .split &&
                (try? profile.validated()) != nil
            matchesNative =
                native.providerBundleIdentifier == AgentConstants.tunnelBundleID &&
                native.serverAddress == profile.endpoint &&
                NativeProfileBindingPolicy.allowsStart(
                    metadata: native.providerConfiguration,
                    profileDigest: try? profile.publicProfileDigest()
                )
        } else {
            isValidSplitProfile = false
            matchesNative = false
        }
        return VPNPrivateChatAccessPolicy.permitsAccess(
            observedConnected: status == .connected,
            nativeConnected: manager?.connection.status == .connected,
            trustedNativeInventory: nativeInventoryTrust.permitsMutation,
            verifiedSplitProfile: isValidSplitProfile,
            nativeProfileBound: matchesNative,
            noPreferenceWriteInFlight: !profileSave.isBusy && !legacyOnDemandDisableInFlight && !routeStop.isPending
        )
    }

    /// The saved App Group on-demand flag can differ from native settings
    /// during legacy remediation. Never display an optimistic write as confirmed.
    var nativeAutoConnectDescription: String {
        guard nativeInventoryTrust.permitsMutation, !profileSave.isBusy,
              !legacyOnDemandDisableInFlight else { return "Not verified" }
        guard let manager else { return "Not configured" }
        return manager.isOnDemandEnabled ? "Enabled" : "Disabled"
    }

    var statusDescription: String {
        switch status {
        case .connected: return canShowPrivateChat ? "Connected" : "Connected — access blocked"
        case .connecting: return "Connecting"
        case .reasserting: return "Reconnecting"
        case .disconnecting: return "Disconnecting"
        case .disconnected: return "Disconnected"
        case .invalid: return "Not configured"
        @unknown default: return "Unknown"
        }
    }
}

import Foundation
import NetworkExtension
import SwiftUI

final class TunnelManager: NSObject, ObservableObject {
    @Published private(set) var status: NEVPNStatus = .invalid
    @Published private(set) var profile: ServerProfile?
    @Published var errorMessage: String?
    @Published var showSettings = false
    private var manager: NETunnelProviderManager?
    private let nativeIO: NativeVPNOperations
    private let profileSave: ProfileSaveSequencer
    private var requestedManualRecovery: UUID?
    private var preferenceJournal: PreferenceWriteJournal { nativeIO.journal() }
    var needsPreferenceRecovery: Bool {
        preferenceJournal.state != .clear && !profileSave.isBusy && !legacyOnDemandDisableInFlight
    }
    var canRecoverInterruptedPreference: Bool {
        if case .pending = preferenceJournal.state { return needsPreferenceRecovery }
        return false
    }
    private struct PendingPreferenceRollback {
        let prior: ServerProfile
        let attempted: ServerProfile
    }
    private var pendingPreferenceRollback: PendingPreferenceRollback?
    private var startingPreferenceRollback = false
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
    @Published private(set) var explicitOptOutInFlight = false
    private var explicitOptOutPrior: ServerProfile?
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

    override convenience init() { self.init(nativeIO: NativeVPNOperations()) }

    init(nativeIO: NativeVPNOperations, profileSave: ProfileSaveSequencer = ProfileSaveSequencer()) {
        self.nativeIO = nativeIO
        self.profileSave = profileSave
        self.profile = nativeIO.loadProfile()
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
            self.status = self.nativeIO.status(self.manager)
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
        let manualRecovery = requestedManualRecovery
        requestedManualRecovery = nil
        let loadToken = preferenceReloadGate.begin()
        nativeInventoryTrust.beginLoad()
        nativeIO.loadAll { [weak self] managers, error in
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
                    self.pendingPreferenceRollback = nil
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
                    self.pendingPreferenceRollback = nil
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
                self.status = self.nativeIO.status(self.manager)
                self.profile = self.nativeIO.loadProfile()
                if let manualRecovery {
                    self.finishManualPreferenceRecovery(manualRecovery)
                }
                if self.preferenceJournal.state != .clear {
                    self.pendingPreferenceRollback = nil
                    self.errorMessage = AgentConfigurationError.preferenceRecoveryRequired.localizedDescription
                    self.remediateLegacyFullTunnel()
                    return
                }
                if self.reconcileFailedPreferenceWrite() { return }
                self.remediateLegacyFullTunnel()
            }
        }
    }

    /// Explicit owner recovery: never remove native preferences ourselves.
    /// The user must first restart iOS and remove the Security Agent VPN
    /// entry in Settings. A fresh load must independently confirm no entry.
    func requestManualPreferenceRecovery() {
        if !Thread.isMainThread {
            DispatchQueue.main.async { [weak self] in self?.requestManualPreferenceRecovery() }
            return
        }
        guard !profileSave.isBusy, !legacyOnDemandDisableInFlight, !routeStop.isPending,
              case .pending(let token) = preferenceJournal.state else {
            errorMessage = AgentConfigurationError.preferenceRecoveryRequired.localizedDescription
            return
        }
        requestedManualRecovery = token
        reload()
    }

    private func finishManualPreferenceRecovery(_ token: UUID) {
        guard PreferenceWriteJournal.permitsManualReset(
            ownerConfirmedRestartAndRemoval: true,
            freshUniqueEmptyInventory: nativeInventoryTrust.permitsMutation && manager == nil,
            nativeOperationInFlight: profileSave.isBusy || legacyOnDemandDisableInFlight
        ) else {
            errorMessage = "Remove the Security Agent VPN entry in iOS Settings, restart the device and retry recovery."
            return
        }
        do {
            try preferenceJournal.finish(token)
            pendingPreferenceRollback = nil
            errorMessage = "Interrupted update cleared. Re-pair your Mac and connect manually."
        } catch {
            errorMessage = AgentConfigurationError.preferenceRecoveryRequired.localizedDescription
        }
    }

    private func finishPreferenceJournal(_ token: UUID) -> Bool {
        do { try preferenceJournal.finish(token); return true }
        catch {
            errorMessage = AgentConfigurationError.preferenceRecoveryRequired.localizedDescription
            return false
        }
    }

    /// Only compare an app-owned, enabled, canonical native configuration.
    /// The prior value is captured by value, not as a mutable NE protocol.
    private func nativeMatches(_ manager: NETunnelProviderManager, _ profile: ServerProfile) -> Bool {
        guard manager.localizedDescription == "Security Agent VPN",
              let digest = try? profile.publicProfileDigest(),
              let native = manager.protocolConfiguration as? NETunnelProviderProtocol else { return false }
        return NativePreferenceCommitVerifier.matches(
            NativePreferenceCommitSnapshot(
                providerBundleIdentifier: native.providerBundleIdentifier,
                serverAddress: native.serverAddress,
                metadata: native.providerConfiguration,
                isEnabled: manager.isEnabled,
                isOnDemandEnabled: manager.isOnDemandEnabled,
                onDemandRuleCount: manager.onDemandRules?.count ?? 0,
                onDemandUsesConnectRule: manager.onDemandRules?.first is NEOnDemandRuleConnect
            ), expectedBundleID: AgentConstants.tunnelBundleID,
            expectedServerAddress: profile.endpoint,
            expectedProfileDigest: digest,
            expectedOnDemand: profile.onDemand
        )
    }

    private func capturePreferenceRollback(to attempted: ServerProfile) -> PendingPreferenceRollback? {
        guard !startingPreferenceRollback, let manager, let prior = profile,
              NativePreferenceRollbackPolicy.canCapture(
                priorVerified: nativeMatches(manager, prior),
                persistedPrior: nativeIO.loadProfile() == prior,
                priorSplit: prior.routeMode == .split,
                attemptedSplit: attempted.routeMode == .split,
                priorOnDemand: prior.onDemand,
                attemptedOnDemand: attempted.onDemand,
                differentProfiles: prior != attempted
              ) else { return nil }
        return PendingPreferenceRollback(prior: prior, attempted: attempted)
    }

    /// Called only after a fresh, current-generation unique/empty inventory.
    /// Consume the plan before any write so a failed repair cannot loop.
    private func reconcileFailedPreferenceWrite() -> Bool {
        guard let plan = pendingPreferenceRollback else { return false }
        pendingPreferenceRollback = nil
        guard let manager else {
            errorMessage = "VPN update failed. No matching system profile was found; re-pair before connecting."
            return false
        }
        switch NativePreferenceRollbackPolicy.decide(
            persistedPrior: nativeIO.loadProfile() == plan.prior,
            trustedInventory: nativeInventoryTrust.permitsMutation,
            nativeDisconnected: nativeIO.status(manager) == .disconnected,
            nativeMatchesPrior: nativeMatches(manager, plan.prior),
            nativeMatchesAttempted: nativeMatches(manager, plan.attempted)
        ) {
        case .unchanged:
            errorMessage = "VPN update failed; the previous verified configuration is still installed."
            return false
        case .manualRepair:
            errorMessage = "VPN update failed and the saved settings cannot be safely restored automatically. Disconnect and re-pair before connecting."
            return false
        case .restore:
            startingPreferenceRollback = true
            defer { startingPreferenceRollback = false }
            // The same save/readback transaction verifies compensation; never
            // auto-reconnect, restore full mode, or re-enable on-demand.
            save(plan.prior)
            return profileSave.isBusy
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
        // A known split session may remain active during the explicit disable
        // transaction. Chat and new starts are blocked by trust/journal.
        // Do not trigger legacy stop/disable while its native write is pending.
        if explicitOptOutInFlight, let prior = explicitOptOutPrior,
           profile == prior, nativeIO.loadProfile() == prior { return }
        let status = nativeIO.status(manager)
        let active = status == .connected || status == .connecting || status == .reasserting
        // A loaded public profile can be stale relative to native system
        // preferences. Only an exact v2 binding certifies a split route;
        // absent or mismatched native metadata is untrusted like missing
        // App Group bytes. Do not assume a running old extension restarted.
        var verifiedRouteIsFull: Bool?
        if preferenceJournal.state == .clear,
           let profile, nativeIO.loadProfile() == profile,
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
            nativeIO.stop(manager)
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
              nativeInventoryTrust.permitsMutation, preferenceJournal.state == .clear else { return }
        let journalToken: UUID
        do { journalToken = try preferenceJournal.begin() }
        catch { errorMessage = AgentConfigurationError.preferenceRecoveryRequired.localizedDescription; return }
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
        nativeIO.schedule(30) { [weak self] in
            guard let self, self.legacyDisableToken == disableToken else { return }
            self.errorMessage = "Legacy VPN auto-connect update has not completed. " +
                "Do not reconnect; check iOS VPN Settings."
        }
        nativeIO.save(manager) { [weak self] error in
            DispatchQueue.main.async {
                guard let self, self.legacyDisableToken == disableToken,
                      self.manager === manager else { return }
                self.legacyDisableToken = nil
                self.legacyOnDemandDisableInFlight = false
                _ = self.finishPreferenceJournal(journalToken)
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
        let nativeStatus = nativeIO.status(manager)
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

        let isCompensation = startingPreferenceRollback
        let rollbackPlan = capturePreferenceRollback(to: validated)
        let journalToken: UUID
        do { journalToken = try preferenceJournal.begin() }
        catch { errorMessage = AgentConfigurationError.preferenceRecoveryRequired.localizedDescription; return }

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

        let io = nativeIO
        profileSave.run(
            saveNative: { callback in io.save(selected, callback) },
            reloadNative: { callback in
                io.reload(selected) { error in
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
            commitPublicProfile: { try io.commitProfile(validated) },
            nativeSettledAfterTimeout: { [weak self] in
                // Never trust a load made before the late OS operation settles.
                guard let self else { return }
                _ = self.finishPreferenceJournal(journalToken)
                self.reload()
            },
            completed: { [weak self] result in
                guard let self else { return }
                switch result {
                case .success:
                    guard self.finishPreferenceJournal(journalToken) else {
                        self.reload()
                        return
                    }
                    self.nativeInventoryTrust.didCommitVerifiedWrite()
                    self.manager = selected
                    self.profile = validated
                    self.status = self.nativeIO.status(selected)
                    self.errorMessage = isCompensation
                        ? "VPN update failed; previous verified split settings restored. Connect manually when ready."
                        : nil
                    if connectAfterSave { self.connect() }
                case .failure(let error):
                    // A failure does not establish native or App Group state.
                    // A single bounded compensation may be eligible only after
                    // fresh inventory and exact public/native readback checks.
                    self.pendingPreferenceRollback = rollbackPlan
                    self.errorMessage = isCompensation
                        ? "VPN recovery failed. Disconnect and re-pair before connecting."
                        : error.localizedDescription
                    if !self.profileSave.isAwaitingNativeCompletion {
                        _ = self.finishPreferenceJournal(journalToken)
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
        guard preferenceJournal.state == .clear else {
            errorMessage = AgentConfigurationError.preferenceRecoveryRequired.localizedDescription
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
        // A matching digest alone is insufficient after a partial native save:
        // verify current public bytes, enabled and exact on-demand settings.
        guard nativeIO.loadProfile() == profile, nativeMatches(manager, profile) else {
            errorMessage = AgentConfigurationError.nativeProfileMismatch.localizedDescription
            return
        }
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
        do { try nativeIO.start(manager) }
        catch { errorMessage = error.localizedDescription }
    }

    func disconnect() {
        if !Thread.isMainThread {
            DispatchQueue.main.async { [weak self] in self?.disconnect() }
            return
        }
        guard !explicitOptOutInFlight else {
            errorMessage = "Wait for system auto-connect to be disabled before disconnecting."
            return
        }
        cancelRouteChange("Route change cancelled. Wait for the VPN to disconnect.")
        if let manager { nativeIO.stop(manager) }
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
              !profileSave.isBusy, !legacyOnDemandDisableInFlight,
              preferenceJournal.state == .clear else {
            errorMessage = "Finish or reload the current VPN configuration before changing routes."
            return
        }
        // On-demand must be disabled and verified first; otherwise the OS
        // may reconnect the old routes before this transaction can commit.
        let nativeStatus = nativeIO.status(manager)
        let disconnected = nativeStatus == .disconnected || (manager == nil && nativeStatus == .invalid)
        guard !(manager?.isOnDemandEnabled ?? false) else {
            errorMessage = "Turn off Connect on demand before changing routing mode."
            return
        }
        let original = updated
        guard nativeIO.loadProfile() == original else {
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
            nativeIO.stop(manager)
        }
        nativeIO.schedule(30) { [weak self] in
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
        let nativeStatus = nativeIO.status(pending.manager)
        let knownStatus = nativeStatus == .disconnected || nativeStatus == .disconnecting ||
            nativeStatus == .connected || nativeStatus == .connecting || nativeStatus == .reasserting
        let valid = manager === pending.manager && profile == pending.original &&
            nativeIO.loadProfile() == pending.original &&
            nativeInventoryTrust.permitsMutation && !pending.manager.isOnDemandEnabled &&
            !profileSave.isBusy && !legacyOnDemandDisableInFlight && knownStatus &&
            preferenceJournal.state == .clear &&
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
        if !enabled && updated.onDemand {
            disableVerifiedOnDemand()
            return
        }
        guard updated.onDemand != enabled else { return }
        updated.onDemand = enabled
        save(updated)
    }

    /// Narrow explicit opt-out, not a relaxation of the generic save policy.
    /// Never edit the running peer, routes or secret material. Stop only
    /// after native disable/readback and public commit, unless a failed
    /// transaction requires fail-closed containment.
    private func disableVerifiedOnDemand() {
        guard nativeInventoryTrust.permitsMutation, !routeStop.isPending,
              !profileSave.isBusy, !legacyOnDemandDisableInFlight,
              !explicitOptOutInFlight, preferenceJournal.state == .clear,
              let manager, let prior = profile, prior.onDemand,
              prior.routeMode == .split, (try? prior.validated()) == prior,
              nativeIO.loadProfile() == prior, nativeMatches(manager, prior),
              let native = manager.protocolConfiguration as? NETunnelProviderProtocol else {
            errorMessage = "Cannot verify the installed VPN for auto-connect opt-out. Reload preferences before retrying."
            return
        }
        let currentStatus = nativeIO.status(manager)
        guard [.disconnected, .connecting, .connected, .reasserting, .disconnecting].contains(currentStatus) else {
            errorMessage = "VPN status is unavailable. Reload preferences before retrying."
            return
        }
        var candidate = prior
        candidate.onDemand = false
        guard let digest = try? candidate.publicProfileDigest() else {
            errorMessage = AgentConfigurationError.nativeProfileMismatch.localizedDescription
            return
        }
        let journalToken: UUID
        do { journalToken = try preferenceJournal.begin() }
        catch { errorMessage = AgentConfigurationError.preferenceRecoveryRequired.localizedDescription; return }

        explicitOptOutPrior = prior
        explicitOptOutInFlight = true
        preferenceReloadGate.invalidate()
        nativeInventoryTrust.beginWrite()
        // Update only the public binding and on-demand settings; retain the
        // exact native protocol, peer, bundle, and enabled state.
        native.providerConfiguration = NativeProfileBindingPolicy.metadata(for: digest)
        manager.protocolConfiguration = native
        manager.isOnDemandEnabled = false
        manager.onDemandRules = []
        let io = nativeIO
        profileSave.run(
            saveNative: { callback in io.save(manager, callback) },
            reloadNative: { [weak self] callback in
                io.reload(manager) { error in
                    DispatchQueue.main.async { [weak self] in
                        if let error { callback(error); return }
                        guard let self, self.manager === manager,
                              self.preferenceJournal.state == .pending(journalToken),
                              io.loadProfile() == prior,
                              self.nativeMatches(manager, candidate) else {
                            callback(AgentConfigurationError.nativeProfileMismatch)
                            return
                        }
                        callback(nil)
                    }
                }
            },
            commitPublicProfile: { [weak self] in
                guard let self, self.manager === manager,
                      self.preferenceJournal.state == .pending(journalToken),
                      io.loadProfile() == prior,
                      self.nativeMatches(manager, candidate) else {
                    throw AgentConfigurationError.nativeProfileMismatch
                }
                try io.commitProfile(candidate)
            },
            nativeSettledAfterTimeout: { [weak self] in
                // A late callback cannot prove the requested opt-out. Retain
                // the durable marker and never replay the write or enable.
                self?.reload()
            },
            completed: { [weak self] result in
                guard let self else { return }
                self.explicitOptOutPrior = nil
                self.explicitOptOutInFlight = false
                switch result {
                case .success:
                    guard self.finishPreferenceJournal(journalToken) else {
                        self.remediateLegacyFullTunnel()
                        self.reload()
                        return
                    }
                    self.nativeInventoryTrust.didCommitVerifiedWrite()
                    self.profile = candidate
                    self.status = self.nativeIO.status(manager)
                    self.errorMessage = nil
                    // The explicit opt-out also requests disconnect, but
                    // only after system auto-connect is verified disabled.
                    if [.connected, .connecting, .reasserting].contains(self.status) {
                        self.nativeIO.stop(manager)
                    }
                case .failure:
                    // No compensation may restore on-demand=true. A failed
                    // or timed-out native result is not proof of unchanged
                    // preferences. Keep the marker across process restart.
                    self.errorMessage = "Could not verify that VPN auto-connect is disabled. Do not reconnect; check iOS VPN Settings and recover the interrupted update."
                    self.remediateLegacyFullTunnel()
                    if !self.profileSave.isAwaitingNativeCompletion { self.reload() }
                }
            }
        )
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
        if let profile, let native, let manager {
            isValidSplitProfile = profile.routeMode == .split &&
                (try? profile.validated()) != nil &&
                nativeIO.loadProfile() == profile
            matchesNative =
                nativeMatches(manager, profile) &&
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
            nativeConnected: nativeIO.status(manager) == .connected,
            trustedNativeInventory: nativeInventoryTrust.permitsMutation,
            verifiedSplitProfile: isValidSplitProfile,
            nativeProfileBound: matchesNative,
            noPreferenceWriteInFlight: !profileSave.isBusy && !legacyOnDemandDisableInFlight && !routeStop.isPending && preferenceJournal.state == .clear
        )
    }

    /// The saved App Group on-demand flag can differ from native settings
    /// during legacy remediation. Never display an optimistic write as confirmed.
    var nativeAutoConnectDescription: String {
        guard nativeInventoryTrust.permitsMutation, !profileSave.isBusy,
              !legacyOnDemandDisableInFlight, preferenceJournal.state == .clear else { return "Not verified" }
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

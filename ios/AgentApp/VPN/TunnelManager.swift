import Foundation
import NetworkExtension
import SwiftUI

final class TunnelManager: NSObject, ObservableObject {
    @Published private(set) var status: NEVPNStatus = .invalid
    @Published private(set) var profile: ServerProfile? = SharedProfileStore.load()
    @Published var errorMessage: String?
    @Published var showSettings = false
    private var manager: NETunnelProviderManager?

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

    func save(_ profile: ServerProfile, connectAfterSave: Bool = false) {
        do { try SharedProfileStore.save(profile) } catch {
            errorMessage = error.localizedDescription
            return
        }
        self.profile = profile
        let configuration = (manager?.protocolConfiguration as? NETunnelProviderProtocol)
            ?? NETunnelProviderProtocol()
        configuration.providerBundleIdentifier = AgentConstants.tunnelBundleID
        configuration.serverAddress = profile.endpoint
        // Public metadata only. No private key, PSK or wg-quick string here.
        configuration.providerConfiguration = ["profileVersion": 1]
        let selected = manager ?? NETunnelProviderManager()
        selected.protocolConfiguration = configuration
        selected.localizedDescription = "Security Agent VPN"
        selected.isEnabled = true
        selected.onDemandRules = profile.onDemand ? [NEOnDemandRuleConnect()] : []
        selected.isOnDemandEnabled = profile.onDemand
        // The app and extension read the same public profile from App Group.
        selected.saveToPreferences { error in
            if let error {
                DispatchQueue.main.async { self.errorMessage = error.localizedDescription }
                return
            }
            selected.loadFromPreferences { error in
                DispatchQueue.main.async {
                    if let error {
                        self.errorMessage = error.localizedDescription
                    } else {
                        self.manager = selected
                        self.status = selected.connection.status
                        if connectAfterSave { self.connect() }
                    }
                }
            }
        }
    }

    func connect() {
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

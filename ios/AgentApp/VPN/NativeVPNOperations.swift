import Foundation
import NetworkExtension

/// Main-queue native I/O boundary. The production defaults are direct
/// NetworkExtension calls; XCTest injects deterministic callbacks and status
/// without touching system VPN preferences or real App Group data.
struct NativeVPNOperations {
    typealias InventoryReply = ([NETunnelProviderManager]?, Error?) -> Void
    typealias WriteReply = (Error?) -> Void

    var loadAll: (@escaping InventoryReply) -> Void = {
        NETunnelProviderManager.loadAllFromPreferences(completionHandler: $0)
    }
    var readStatus: (NETunnelProviderManager) -> NEVPNStatus = { $0.connection.status }
    var stop: (NETunnelProviderManager) -> Void = { $0.connection.stopVPNTunnel() }
    var start: (NETunnelProviderManager) throws -> Void = { try $0.connection.startVPNTunnel() }
    var save: (NETunnelProviderManager, @escaping WriteReply) -> Void = {
        $0.saveToPreferences(completionHandler: $1)
    }
    var reload: (NETunnelProviderManager, @escaping WriteReply) -> Void = {
        $0.loadFromPreferences(completionHandler: $1)
    }
    var loadProfile: () -> ServerProfile? = { SharedProfileStore.load() }
    var commitProfile: (ServerProfile) throws -> Void = { try SharedProfileStore.save($0) }
    var journal: () -> PreferenceWriteJournal = { SharedPreferenceWriteJournal.current }
    var schedule: (TimeInterval, @escaping () -> Void) -> Void = { seconds, work in
        DispatchQueue.main.asyncAfter(deadline: .now() + seconds, execute: work)
    }

    func status(_ manager: NETunnelProviderManager?) -> NEVPNStatus {
        manager.map(readStatus) ?? .invalid
    }
}

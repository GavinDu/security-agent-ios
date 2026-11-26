import Foundation
import NetworkExtension
import XCTest
@testable import AgentApp

/// Fake callbacks exercise the actual TunnelManager, not a test-only copy
/// of its state machine. NETunnelProviderManager is only a local config
/// value carrier here; no OS preferences or real App Group are touched.
private final class FakeNativeVPN {
    enum Failure: Error { case denied, readback }
    var state: NEVPNStatus = .disconnected
    var persisted: ServerProfile?
    var stops = 0
    var starts = 0
    var inventories: [NativeVPNOperations.InventoryReply] = []
    var saves: [(NETunnelProviderManager, NativeVPNOperations.WriteReply)] = []
    var reloads: [(NETunnelProviderManager, NativeVPNOperations.WriteReply)] = []
    var deadlines: [() -> Void] = []
    var commits: [ServerProfile] = []
    let directory: URL

    init(_ profile: ServerProfile?) throws {
        persisted = profile
        directory = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false)
    }

    deinit { try? FileManager.default.removeItem(at: directory) }

    var journal: PreferenceWriteJournal { PreferenceWriteJournal(directory: directory) }

    func operations() -> NativeVPNOperations {
        var io = NativeVPNOperations()
        io.loadAll = { self.inventories.append($0) }
        io.readStatus = { _ in self.state }
        io.stop = { _ in self.stops += 1 }
        io.start = { _ in self.starts += 1 }
        io.save = { self.saves.append(($0, $1)) }
        io.reload = { self.reloads.append(($0, $1)) }
        io.loadProfile = { self.persisted }
        io.commitProfile = { self.persisted = $0; self.commits.append($0) }
        io.journal = { self.journal }
        io.schedule = { _, work in self.deadlines.append(work) }
        return io
    }

    func installed(_ profile: ServerProfile) throws -> NETunnelProviderManager {
        let manager = NETunnelProviderManager()
        let configuration = NETunnelProviderProtocol()
        configuration.providerBundleIdentifier = AgentConstants.tunnelBundleID
        configuration.serverAddress = profile.endpoint
        configuration.providerConfiguration = NativeProfileBindingPolicy.metadata(
            for: try profile.publicProfileDigest())
        manager.protocolConfiguration = configuration
        manager.localizedDescription = "Security Agent VPN"
        manager.isEnabled = true
        manager.onDemandRules = profile.onDemand ? [NEOnDemandRuleConnect()] : []
        manager.isOnDemandEnabled = profile.onDemand
        return manager
    }

    func notify(_ state: NEVPNStatus) {
        self.state = state
        NotificationCenter.default.post(name: .NEVPNStatusDidChange, object: nil)
    }
}

final class TunnelManagerNativeIntegrationTests: XCTestCase {
    private func profile(_ mode: RouteMode = .split, onDemand: Bool = false,
                         endpoint: String = "198.51.100.9:51820") -> ServerProfile {
        ServerProfile(publicKey: Data(repeating: 7, count: 32).base64EncodedString(),
                      endpoint: endpoint, routeMode: mode, onDemand: onDemand)
    }

    private func awaitState(_ description: String, file: StaticString = #filePath,
                            line: UInt = #line, _ condition: () -> Bool) {
        let end = Date().addingTimeInterval(3)
        while !condition() && Date() < end {
            _ = RunLoop.current.run(mode: .default, before: Date().addingTimeInterval(0.01))
        }
        XCTAssertTrue(condition(), description, file: file, line: line)
    }

    private func drainMain() {
        let drained = expectation(description: "main callbacks drained")
        DispatchQueue.main.async { drained.fulfill() }
        wait(for: [drained], timeout: 3)
    }

    func testInitialPermissionDenialDoesNotPublishOrConnectAndRetryIsExplicit() throws {
        let candidate = profile()
        let fake = try FakeNativeVPN(nil)
        let tunnel = TunnelManager(nativeIO: fake.operations())
        fake.inventories[0]([], nil)
        drainMain()
        tunnel.save(candidate, connectAfterSave: true)
        XCTAssertEqual(fake.saves.count, 1)
        XCTAssertNotEqual(fake.journal.state, .clear)
        XCTAssertNil(tunnel.profile)
        fake.saves[0].1(FakeNativeVPN.Failure.denied)
        awaitState("fresh inventory after denied initial save") { fake.inventories.count == 2 }
        XCTAssertNil(fake.persisted)
        XCTAssertNil(tunnel.profile)
        XCTAssertTrue(fake.commits.isEmpty)
        XCTAssertTrue(fake.reloads.isEmpty)
        XCTAssertEqual(fake.starts, 0)
        XCTAssertNotNil(tunnel.errorMessage)
        fake.inventories[1]([], nil)
        drainMain()
        XCTAssertEqual(fake.journal.state, .clear)
        tunnel.connect()
        XCTAssertEqual(fake.starts, 0)
        // Only the user's explicit retry may create a new native write.
        tunnel.save(candidate, connectAfterSave: true)
        XCTAssertEqual(fake.saves.count, 2)
        fake.saves[1].1(nil)
        awaitState("native reload on explicit retry") { fake.reloads.count == 1 }
        XCTAssertNil(fake.persisted)
        XCTAssertEqual(fake.starts, 0)
        fake.reloads[0].1(nil)
        awaitState("verified publication and explicit connect") { fake.starts == 1 }
        XCTAssertEqual(fake.commits, [candidate])
        XCTAssertEqual(tunnel.profile, candidate)
        XCTAssertEqual(fake.journal.state, .clear)
    }

    func testRelaunchRestoresActualNativeStatusAndObservesTransitionsWithoutWrite() throws {
        let prior = profile()
        let fake = try FakeNativeVPN(prior)
        fake.state = .connected
        let tunnel = TunnelManager(nativeIO: fake.operations())
        XCTAssertEqual(tunnel.status, .invalid)
        fake.inventories[0]([try fake.installed(prior)], nil)
        awaitState("relaunch reads installed manager status") { tunnel.status == .connected }
        XCTAssertEqual(tunnel.profile, prior)
        fake.notify(.disconnecting)
        awaitState("native status observer") { tunnel.status == .disconnecting }
        fake.notify(.disconnected)
        awaitState("native disconnected observer") { tunnel.status == .disconnected }
        XCTAssertTrue(fake.saves.isEmpty)
        XCTAssertTrue(fake.commits.isEmpty)
        XCTAssertEqual(fake.starts, 0)
        XCTAssertEqual(fake.stops, 0)
        XCTAssertEqual(fake.journal.state, .clear)
    }

    func testActiveLegacyRouteWaitsForActualDisconnectAndNeverReconnects() throws {
        let prior = profile(.full)
        let fake = try FakeNativeVPN(prior)
        fake.state = .connected
        let tunnel = TunnelManager(nativeIO: fake.operations())
        let installed = try fake.installed(prior)
        fake.inventories[0]([installed], nil)
        awaitState("legacy stop requested") { fake.stops == 1 }
        tunnel.changeRoute(to: .split)
        XCTAssertTrue(tunnel.isChangingRoute)
        XCTAssertEqual(fake.stops, 1)
        XCTAssertTrue(fake.saves.isEmpty)
        fake.notify(.disconnecting)
        drainMain()
        XCTAssertTrue(fake.saves.isEmpty)
        fake.notify(.disconnected)
        awaitState("native save after acknowledged disconnect") { fake.saves.count == 1 }
        XCTAssertEqual(fake.persisted, prior)
        XCTAssertNotEqual(fake.journal.state, .clear)
        fake.saves[0].1(nil)
        awaitState("native readback started") { fake.reloads.count == 1 }
        XCTAssertEqual(fake.persisted, prior)
        fake.reloads[0].1(nil)
        awaitState("split profile published") { tunnel.profile?.routeMode == .split }
        XCTAssertEqual(fake.commits.count, 1)
        XCTAssertEqual(fake.journal.state, .clear)
        XCTAssertEqual(fake.starts, 0)
        fake.deadlines.forEach { $0() }
        drainMain()
        XCTAssertEqual(fake.saves.count, 1)
        tunnel.connect()
        XCTAssertEqual(fake.starts, 1)
    }

    func testFullSelectionDoesNotStopVerifiedSplit() throws {
        let prior = profile()
        let fake = try FakeNativeVPN(prior)
        fake.state = .connected
        let tunnel = TunnelManager(nativeIO: fake.operations())
        fake.inventories[0]([try fake.installed(prior)], nil)
        awaitState("native split connected") { tunnel.status == .connected }
        tunnel.changeRoute(to: .full)
        XCTAssertEqual(fake.stops, 0)
        XCTAssertTrue(fake.saves.isEmpty)
        XCTAssertEqual(fake.persisted, prior)
        XCTAssertNotNil(tunnel.errorMessage)
    }

    func testLegacyOnDemandDenialAndDuplicateCallbackDoNotRetry() throws {
        let prior = profile(.full, onDemand: true)
        let fake = try FakeNativeVPN(prior)
        fake.state = .connected
        let tunnel = TunnelManager(nativeIO: fake.operations())
        fake.inventories[0]([try fake.installed(prior)], nil)
        awaitState("legacy stop and disable") { fake.saves.count == 1 && fake.stops == 1 }
        XCTAssertFalse(fake.saves[0].0.isOnDemandEnabled)
        fake.deadlines.forEach { $0() }
        XCTAssertNotEqual(fake.journal.state, .clear)
        fake.saves[0].1(FakeNativeVPN.Failure.denied)
        awaitState("reload after denial") { fake.inventories.count == 2 }
        fake.saves[0].1(nil)
        fake.inventories[1]([try fake.installed(prior)], nil)
        drainMain()
        XCTAssertEqual(fake.inventories.count, 2)
        XCTAssertEqual(fake.saves.count, 1)
        XCTAssertEqual(fake.persisted, prior)
        XCTAssertFalse(tunnel.canShowPrivateChat)
        tunnel.connect()
        XCTAssertEqual(fake.starts, 0)
    }

    func testRouteDeadlineCannotCommitOnLateDisconnect() throws {
        let prior = profile(.full)
        let fake = try FakeNativeVPN(prior)
        fake.state = .connected
        let tunnel = TunnelManager(nativeIO: fake.operations())
        fake.inventories[0]([try fake.installed(prior)], nil)
        awaitState("legacy stop requested") { fake.stops == 1 }
        tunnel.changeRoute(to: .split)
        XCTAssertTrue(tunnel.isChangingRoute)
        XCTAssertEqual(fake.deadlines.count, 1)
        fake.deadlines[0]()
        XCTAssertFalse(tunnel.isChangingRoute)
        fake.notify(.disconnected)
        drainMain()
        XCTAssertTrue(fake.saves.isEmpty)
        XCTAssertEqual(fake.persisted, prior)
    }

    func testFailedReadbackCompensatesOnceWithoutReconnect() throws {
        let prior = profile()
        let attempted = profile(endpoint: "198.51.100.10:51820")
        let fake = try FakeNativeVPN(prior)
        let tunnel = TunnelManager(nativeIO: fake.operations())
        let installed = try fake.installed(prior)
        fake.inventories[0]([installed], nil)
        awaitState("initial inventory") { tunnel.status == .disconnected }
        tunnel.save(attempted)
        XCTAssertEqual(fake.saves.count, 1)
        fake.saves[0].1(nil)
        awaitState("attempted readback") { fake.reloads.count == 1 }
        fake.reloads[0].1(FakeNativeVPN.Failure.readback)
        awaitState("fresh inventory requested") { fake.inventories.count == 2 }
        XCTAssertEqual(fake.persisted, prior)
        fake.inventories[1]([try fake.installed(attempted)], nil)
        awaitState("compensating save") { fake.saves.count == 2 }
        XCTAssertEqual((fake.saves[1].0.protocolConfiguration as? NETunnelProviderProtocol)?.serverAddress,
                       prior.endpoint)
        fake.saves[1].1(nil)
        awaitState("compensation readback") { fake.reloads.count == 2 }
        fake.reloads[1].1(nil)
        awaitState("compensation published") { fake.commits == [prior] && fake.journal.state == .clear }
        XCTAssertEqual(fake.starts, 0)
        XCTAssertEqual(fake.saves.count, 2)
    }

    func testRestartMarkerBlocksUntilExplicitRecoveryAndEmptyInventory() throws {
        let prior = profile()
        let fake = try FakeNativeVPN(prior)
        let token = try fake.journal.begin()
        let tunnel = TunnelManager(nativeIO: fake.operations())
        fake.inventories[0]([try fake.installed(prior)], nil)
        awaitState("interrupted inventory") { tunnel.status == .disconnected }
        XCTAssertTrue(tunnel.needsPreferenceRecovery)
        tunnel.connect()
        tunnel.save(prior)
        XCTAssertEqual(fake.starts, 0)
        XCTAssertTrue(fake.saves.isEmpty)
        tunnel.requestManualPreferenceRecovery()
        XCTAssertEqual(fake.inventories.count, 2)
        fake.inventories[1]([try fake.installed(prior)], nil)
        drainMain()
        XCTAssertEqual(fake.journal.state, .pending(token))
        tunnel.requestManualPreferenceRecovery()
        XCTAssertEqual(fake.inventories.count, 3)
        fake.inventories[2]([], nil)
        awaitState("explicit recovery verified empty inventory") { fake.journal.state == .clear }
        XCTAssertFalse(tunnel.needsPreferenceRecovery)
        XCTAssertEqual(fake.starts, 0)
        XCTAssertTrue(fake.saves.isEmpty)
    }

    func testLegacyConnectingReassertingAndInactiveStates() throws {
        for status in [NEVPNStatus.connecting, .reasserting, .disconnected] {
            let prior = profile(.full)
            let fake = try FakeNativeVPN(prior)
            fake.state = status
            let tunnel = TunnelManager(nativeIO: fake.operations())
            fake.inventories[0]([try fake.installed(prior)], nil)
            awaitState("legacy inventory published") { tunnel.status == status }
            XCTAssertEqual(fake.stops, status == .disconnected ? 0 : 1)
            XCTAssertFalse(tunnel.canShowPrivateChat)
            tunnel.connect()
            XCTAssertEqual(fake.starts, 0)
            XCTAssertTrue(fake.saves.isEmpty)
        }
    }

    func testRapidRouteSelectionsAndOfflineReassertionDoNotOverlapWrites() throws {
        let prior = profile(.full)
        let fake = try FakeNativeVPN(prior)
        fake.state = .reasserting
        let tunnel = TunnelManager(nativeIO: fake.operations())
        fake.inventories[0]([try fake.installed(prior)], nil)
        awaitState("legacy reassertion stopped") { fake.stops == 1 }
        tunnel.changeRoute(to: .split)
        for _ in 0..<10 {
            tunnel.changeRoute(to: .split)
            tunnel.changeRoute(to: .full)
        }
        XCTAssertTrue(tunnel.isChangingRoute)
        XCTAssertEqual(fake.stops, 1)
        XCTAssertEqual(fake.deadlines.count, 1)
        fake.notify(.reasserting)
        drainMain()
        XCTAssertTrue(fake.saves.isEmpty)
        fake.notify(.disconnected)
        awaitState("one native save") { fake.saves.count == 1 }
        tunnel.changeRoute(to: .split)
        fake.notify(.disconnected)
        drainMain()
        XCTAssertEqual(fake.saves.count, 1)
        XCTAssertEqual(fake.persisted, prior)
        fake.saves[0].1(nil)
        awaitState("one readback") { fake.reloads.count == 1 }
        fake.reloads[0].1(nil)
        awaitState("one split commit") { fake.commits.count == 1 }
        XCTAssertEqual(tunnel.profile?.routeMode, .split)
        XCTAssertEqual(fake.starts, 0)
    }

    func testDuplicateInventoryAndStaleLoadCannotAuthorizeLegacyMutation() throws {
        let prior = profile(.full, onDemand: true)
        let fake = try FakeNativeVPN(prior)
        fake.state = .connected
        let tunnel = TunnelManager(nativeIO: fake.operations())
        let stale = fake.inventories[0]
        tunnel.reload()
        XCTAssertEqual(fake.inventories.count, 2)
        fake.inventories[1]([try fake.installed(prior), try fake.installed(prior)], nil)
        drainMain()
        stale([try fake.installed(prior)], nil)
        drainMain()
        XCTAssertEqual(tunnel.status, .invalid)
        XCTAssertEqual(fake.stops, 0)
        XCTAssertTrue(fake.saves.isEmpty)
        XCTAssertFalse(tunnel.canShowPrivateChat)
        tunnel.connect()
        XCTAssertEqual(fake.starts, 0)
        XCTAssertEqual(fake.journal.state, .clear)
    }

    func testLegacyOnDemandSuccessRequiresFreshReadbackBeforeMigration() throws {
        let prior = profile(.full, onDemand: true)
        let fake = try FakeNativeVPN(prior)
        fake.state = .connecting
        let tunnel = TunnelManager(nativeIO: fake.operations())
        fake.inventories[0]([try fake.installed(prior)], nil)
        awaitState("legacy disable submitted") { fake.saves.count == 1 }
        tunnel.changeRoute(to: .split)
        XCTAssertFalse(tunnel.isChangingRoute)
        XCTAssertEqual(fake.saves.count, 1)
        fake.saves[0].1(nil)
        awaitState("legacy disable fresh inventory") { fake.inventories.count == 2 }
        let reloaded = try fake.installed(prior)
        reloaded.isOnDemandEnabled = false
        reloaded.onDemandRules = []
        fake.state = .disconnected
        fake.inventories[1]([reloaded], nil)
        awaitState("native on-demand confirmed disabled") { tunnel.nativeAutoConnectDescription == "Disabled" }
        tunnel.changeRoute(to: .split)
        XCTAssertEqual(fake.saves.count, 2)
        fake.saves[1].1(nil)
        awaitState("split readback") { fake.reloads.count == 1 }
        fake.reloads[0].1(nil)
        awaitState("split profile committed") { tunnel.profile?.routeMode == .split }
        XCTAssertEqual(fake.commits.count, 1)
        XCTAssertEqual(fake.starts, 0)
        XCTAssertEqual(fake.journal.state, .clear)
    }

}

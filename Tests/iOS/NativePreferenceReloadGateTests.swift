import XCTest
@testable import AgentApp

final class NativePreferenceReloadGateTests: XCTestCase {
    func testOlderLoadCannotPublishAfterNewerLoad() {
        var gate = NativePreferenceReloadGate()
        var published: [String] = []
        let first = gate.begin()
        let second = gate.begin()

        // Simulate out-of-order loadAllFromPreferences completions.
        for (token, value) in [(first, "old"), (second, "new")] {
            if gate.disposition(
                for: token, writeInFlight: false, loadSucceeded: true
            ) == .publish {
                published.append(value)
            }
        }
        XCTAssertEqual(published, ["new"])
    }

    func testNativeSaveInvalidatesOutstandingReadAndBlocksInflightRead() {
        var gate = NativePreferenceReloadGate()
        let pending = gate.begin()
        gate.invalidate() // TunnelManager.save begins native mutation
        XCTAssertEqual(
            gate.disposition(for: pending, writeInFlight: false, loadSucceeded: true),
            .discard
        )
        let current = gate.begin()
        XCTAssertEqual(
            gate.disposition(for: current, writeInFlight: true, loadSucceeded: true),
            .discard
        )
    }

    func testFailedOrObsoleteLoadCannotReplaceConfirmedManager() {
        var gate = NativePreferenceReloadGate()
        let first = gate.begin()
        XCTAssertEqual(
            gate.disposition(for: first, writeInFlight: false, loadSucceeded: false),
            .reportFailure
        )
        let second = gate.begin()
        XCTAssertEqual(
            gate.disposition(for: first, writeInFlight: false, loadSucceeded: false),
            .discard
        )
        XCTAssertEqual(
            gate.disposition(for: second, writeInFlight: false, loadSucceeded: true),
            .publish
        )
    }
}

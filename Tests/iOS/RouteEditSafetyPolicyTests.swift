import XCTest
@testable import AgentApp

final class RouteEditSafetyPolicyTests: XCTestCase {
    func testStopGateRejectsStaleTimeoutAndDuplicateAcknowledgement() throws {
        var gate = RouteStopTransaction()
        let first = try XCTUnwrap(gate.begin())
        XCTAssertNil(gate.begin())
        XCTAssertEqual(gate.observe(first, disconnected: false, contextValid: true), .waiting)
        XCTAssertTrue(gate.cancel(first))
        let second = try XCTUnwrap(gate.begin())
        XCTAssertFalse(gate.cancel(first))
        XCTAssertEqual(gate.observe(first, disconnected: true, contextValid: true), .ignored)
        XCTAssertEqual(gate.observe(second, disconnected: true, contextValid: true), .commit)
        XCTAssertEqual(gate.observe(second, disconnected: true, contextValid: true), .ignored)
        XCTAssertFalse(gate.isPending)
    }

    func testDisconnectCannotCommitIfContextChanged() throws {
        var gate = RouteStopTransaction()
        let token = try XCTUnwrap(gate.begin())
        XCTAssertEqual(gate.observe(token, disconnected: true, contextValid: false), .cancelled)
        XCTAssertFalse(gate.isPending)
    }

    func testRouteEditingRequiresDisconnectedAndDisabledOnDemand() {
        XCTAssertTrue(RouteEditSafetyPolicy.permitsEdit(
            nativeDisconnected: true,
            nativeOnDemandEnabled: false,
            saveInFlight: false
        ))
        for disconnected in [false, true] {
            for onDemand in [false, true] {
                for busy in [false, true] {
                    let permitted = RouteEditSafetyPolicy.permitsEdit(
                        nativeDisconnected: disconnected,
                        nativeOnDemandEnabled: onDemand,
                        saveInFlight: busy
                    )
                    XCTAssertEqual(permitted, disconnected && !onDemand && !busy)
                }
            }
        }
    }
}

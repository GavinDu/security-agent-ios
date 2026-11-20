import XCTest
@testable import AgentApp

final class RouteEditSafetyPolicyTests: XCTestCase {
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

import XCTest
@testable import AgentApp

final class TunnelRouteSafetyPolicyTests: XCTestCase {
    func testSplitModeStillAvailable() {
        XCTAssertTrue(TunnelRouteSafetyPolicy.permitsStart(.split))
    }

    func testFullModeFailsClosedBeforeNativeRoutes() {
        XCTAssertFalse(TunnelRouteSafetyPolicy.permitsStart(.full))
        XCTAssertEqual(
            AgentConfigurationError.unverifiedFullTunnel.localizedDescription,
            "Full tunnel is disabled until encrypted UDP underlay routing and leak safety pass physical iPhone tests. Use split tunnel."
        )
    }
}

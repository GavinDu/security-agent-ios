import XCTest
@testable import AgentApp

final class UnsafeUnderlayEndpointMessageTests: XCTestCase {
    func testUnsafeEndpointDescriptionExplainsActualUnicastAndDNSPreflight() {
        guard let message = AgentConfigurationError.unsafeUnderlayEndpoint.errorDescription else {
            XCTFail("Missing actionable WireGuard underlay safety error")
            return
        }
        XCTAssertTrue(message.contains("unicast"))
        XCTAssertTrue(message.contains("outside the VPN split routes"))
        XCTAssertTrue(message.contains("resolved A/AAAA addresses are all safe"))
        for unsafeClass in ["Loopback", "link-local", "multicast", "broadcast"] {
            XCTAssertTrue(message.contains(unsafeClass), unsafeClass)
        }
        XCTAssertFalse(message.contains("full tunnel"))
        XCTAssertFalse(message.contains("any hostname"))
    }
}

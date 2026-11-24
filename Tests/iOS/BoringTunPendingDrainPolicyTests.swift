import XCTest
@testable import AgentApp

final class BoringTunPendingDrainPolicyTests: XCTestCase {
    func testDoneAndFullQueueTerminate() throws {
        for outputs in [0, 1, 2, 256] {
            var calls = 0
            try BoringTunPendingDrainPolicy.drain {
                calls += 1
                return calls <= outputs
            }
            XCTAssertEqual(calls, outputs + 1)
        }
    }

    func testNeverEndingEngineAndLocalErrorFailClosed() {
        var calls = 0
        XCTAssertThrowsError(try BoringTunPendingDrainPolicy.drain {
            calls += 1
            return true
        }) { error in
            XCTAssertTrue(error is BoringTunPendingDrainPolicy.Failure)
        }
        XCTAssertEqual(calls, 257)
        enum LocalFailure: Error { case injected }
        calls = 0
        XCTAssertThrowsError(try BoringTunPendingDrainPolicy.drain {
            calls += 1
            throw LocalFailure.injected
        }) { error in
            XCTAssertTrue(error is LocalFailure)
        }
        XCTAssertEqual(calls, 1)
    }
}

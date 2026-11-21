import Foundation
import XCTest
@testable import AgentApp

final class AsyncUnderlayDNSResolverTests: XCTestCase {
    func testSuccessfulNumericAnswerOnConfiguredCallbackQueue() {
        let done = expectation(description: "already resolved A/AAAA answer")
        let resolver = AsyncUnderlayDNSResolver(lookup: { host in
            XCTAssertEqual(host, "home.example.test")
            return ["203.0.113.42", "2001:db8::1"]
        })
        resolver.resolve(host: "home.example.test",
                         callbackQueue: DispatchQueue(label: "dns-test", qos: .userInitiated)) { result in
            switch result {
            case .success(let addresses):
                XCTAssertEqual(addresses, ["203.0.113.42", "2001:db8::1"])
            case .failure(let error):
                XCTFail("Unexpected DNS failure: \(error)")
            }
            done.fulfill()
        }
        wait(for: [done], timeout: 15)
    }

    // Under macOS Actions heavy parallel simulator load, dispatch scheduling
    // alone can exceed five seconds; do not confuse scheduler starvation
    // with an invalid DNS response. Keep result assertions and the resolver's
    // production default timeout unchanged; only XCTest wall clock is wider.
    func testEmptyAndErrorResponsesFailClosed() {
        let empty = expectation(description: "empty lookup")
        let resolver = AsyncUnderlayDNSResolver(lookup: { _ in [] })
        resolver.resolve(host: "empty.test",
                         callbackQueue: DispatchQueue(label: "dns-empty", qos: .userInitiated)) { result in
            if case .failure(.noAddresses) = result {} else {
                XCTFail("Empty DNS answer accepted")
            }
            empty.fulfill()
        }
        wait(for: [empty], timeout: 15)
    }

    func testUnresponsiveLookupTimesOutAndSecondAttemptIsRejected() {
        let done = expectation(description: "timeout and single-flight refusal")
        done.expectedFulfillmentCount = 2
        let release = DispatchSemaphore(value: 0)
        let queue = DispatchQueue(label: "dns-timeout", qos: .userInitiated)
        let resolver = AsyncUnderlayDNSResolver(lookup: { _ in
            release.wait()
            return ["203.0.113.42"]
        })
        resolver.resolve(host: "slow.test", timeout: 0.05, callbackQueue: queue) { result in
            if case .failure(.timedOut) = result {} else { XCTFail("Expected timeout") }
            done.fulfill()
        }
        resolver.resolve(host: "busy.test", timeout: 1, callbackQueue: queue) { result in
            if case .failure(.busy) = result {} else { XCTFail("Expected busy refusal") }
            done.fulfill()
        }
        wait(for: [done], timeout: 15)
        release.signal()
    }
}

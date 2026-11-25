import Foundation
import XCTest
@testable import AgentApp

final class AsyncUnderlayDNSResolverTests: XCTestCase {
    func testTypedDiagnosticCodesAreDistinctAllowlistedAndExportable() {
        let diagnosticCases: [(UnderlayDNSResolutionError, String)] = [
            (.busy, "dns_preflight_busy"), (.timedOut, "dns_preflight_timeout"),
            (.noAddresses, "dns_preflight_empty"), (.lookupFailed, "dns_preflight_failed")
        ]
        for (reason, code) in diagnosticCases {
            XCTAssertEqual(reason.diagnosticEventCode, code)
            XCTAssertTrue(VPNEventHistory.allows(code))
            let event = VPNEvent(id: UUID(), at: Date(timeIntervalSince1970: 1_700_000_000), event: code)
            XCTAssertTrue(VPNEventExport.redactedText(from: [event]).contains(code))
        }
        XCTAssertEqual(Set(diagnosticCases.map { $0.0.diagnosticEventCode }).count, 4)
        XCTAssertTrue(VPNEventHistory.allows("unsafe_underlay_rejected"))
        XCTAssertFalse(VPNEventHistory.allows("dns_preflight_failed: private.example"))
    }

    func testDNSFailuresHaveRedactedDistinctDescriptions() {
        let expected: [(UnderlayDNSResolutionError, String)] = [
            (.busy, "A previous VPN DNS lookup is still running; reconnect after it finishes."),
            (.timedOut, "VPN server DNS lookup timed out; check connectivity and reconnect."),
            (.noAddresses, "VPN server DNS lookup returned no usable IP addresses."),
            (.lookupFailed, "Unable to resolve the VPN server address; check DNS and reconnect.")
        ]
        for (reason, message) in expected {
            XCTAssertEqual(reason.errorDescription, message)
            XCTAssertEqual(reason.localizedDescription, message)
            XCTAssertFalse(message.contains("Rust"))
            XCTAssertFalse(message.contains("home.example.test"))
        }
        XCTAssertEqual(Set(expected.map { $0.1 }).count, 4)
    }

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

    func testUnsafeHostInputNeverInvokesDNSLookup() {
        let hosts = [
            "home.example.test\n", "home\t.example.test",
            "home example.test", "home.example.test\u{0085}",
            "fe80::1%en0", "[2001:db8::1]",
            "home.example.test\u{007F}"
        ]
        let done = expectation(description: "reject unsafe underlay host before lookup")
        done.expectedFulfillmentCount = hosts.count
        let resolver = AsyncUnderlayDNSResolver(lookup: { _ in
            XCTFail("Malformed or scoped host reached getaddrinfo boundary")
            return ["203.0.113.42"]
        })
        let queue = DispatchQueue(label: "dns-host-input-test")
        for host in hosts {
            resolver.resolve(host: host, callbackQueue: queue) { result in
                if case .failure(.lookupFailed) = result {} else {
                    XCTFail("Unsafe underlay hostname was not rejected: \(host)")
                }
                done.fulfill()
            }
        }
        wait(for: [done], timeout: 15)
    }

    func testUnbracketedNumericIPv6StillAcceptedForLookup() {
        let done = expectation(description: "unbracketed numeric IPv6")
        let resolver = AsyncUnderlayDNSResolver(lookup: { host in
            XCTAssertEqual(host, "2001:db8::1")
            return ["2001:db8::1"]
        })
        resolver.resolve(host: "2001:db8::1",
                         callbackQueue: DispatchQueue(label: "dns-ipv6-test")) { result in
            switch result {
            case .success(let addresses):
                XCTAssertEqual(addresses, ["2001:db8::1"])
            case .failure(let error):
                XCTFail("Valid unbracketed IPv6 rejected: \(error)")
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

    func testExpiredNumericAnswerCannotReachDelayedTransportQueue() {
        let callbackQueue = DispatchQueue(label: "dns-delayed-transport")
        callbackQueue.suspend()
        let workerReturned = expectation(description: "DNS worker returned")
        let expired = expectation(description: "expired numeric result rejected")
        let resolver = AsyncUnderlayDNSResolver(lookup: { _ in
            workerReturned.fulfill()
            return ["203.0.113.42"]
        })
        resolver.resolve(host: "expired.test", timeout: 0.1,
                         callbackQueue: callbackQueue) { result in
            if case .failure(.timedOut) = result {} else {
                XCTFail("Expired DNS result could install tunnel routes")
            }
            expired.fulfill()
        }
        wait(for: [workerReturned], timeout: 15)
        let delay = expectation(description: "monotonic deadline elapsed")
        DispatchQueue.global().asyncAfter(deadline: .now() + .milliseconds(200)) {
            delay.fulfill()
        }
        wait(for: [delay], timeout: 15)
        callbackQueue.resume()
        wait(for: [expired], timeout: 15)
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

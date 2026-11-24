import Foundation
import XCTest
@testable import AgentApp

final class AsyncUnderlayDNSCancellationTests: XCTestCase {
    func testCancelledMalformedHostCannotDeliverAlreadyQueuedCallback() {
        let callbackQueue = DispatchQueue(label: "canceled-underlay-invalid-host")
        let blocked = expectation(description: "callback queue blocked")
        let release = DispatchSemaphore(value: 0)
        callbackQueue.async {
            blocked.fulfill()
            release.wait()
        }
        wait(for: [blocked], timeout: 15)
        let callback = expectation(description: "canceled invalid host result")
        callback.isInverted = true
        let resolver = AsyncUnderlayDNSResolver(lookup: { _ in
            XCTFail("Invalid host reached DNS worker")
            return []
        })
        let cancellation = resolver.resolve(
            host: "invalid\n.example", callbackQueue: callbackQueue
        ) { _ in callback.fulfill() }
        cancellation.cancel()
        release.signal()
        let drained = expectation(description: "callback queue drained")
        callbackQueue.async { drained.fulfill() }
        wait(for: [drained], timeout: 15)
        wait(for: [callback], timeout: 0.25)
    }

    func testCanceledBlockedLookupStillRefusesConcurrentWorker() {
        let entered = expectation(description: "DNS lookup blocked")
        let release = DispatchSemaphore(value: 0)
        let callbackQueue = DispatchQueue(label: "canceled-underlay-busy")
        let resolver = AsyncUnderlayDNSResolver(lookup: { _ in
            entered.fulfill()
            release.wait()
            return ["203.0.113.42"]
        })
        let canceledCallback = expectation(description: "obsolete DNS completion")
        canceledCallback.isInverted = true
        let cancel = resolver.resolve(
            host: "pending.example", timeout: 1, callbackQueue: callbackQueue
        ) { _ in canceledCallback.fulfill() }
        wait(for: [entered], timeout: 15)
        cancel.cancel()
        let busy = expectation(description: "busy until native worker returns")
        _ = resolver.resolve(host: "later.example", callbackQueue: callbackQueue) { result in
            if case .failure(.busy) = result {} else {
                XCTFail("Canceled DNS lookup released single-flight worker early")
            }
            busy.fulfill()
        }
        wait(for: [busy], timeout: 15)
        release.signal()
        wait(for: [canceledCallback], timeout: 0.25)
    }
}

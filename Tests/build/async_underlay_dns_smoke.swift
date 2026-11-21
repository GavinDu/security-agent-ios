import Foundation

@main
struct AsyncUnderlayDNSSmoke {
    static func main() {
        let callbackQueue = DispatchQueue(label: "test-underlay-dns")
        func assertResult(
            lookup: @escaping AsyncUnderlayDNSResolver.Lookup,
            host: String = "home.example.test", timeout: TimeInterval = 1,
            expected: Result<[String], UnderlayDNSResolutionError>
        ) {
            let done = DispatchSemaphore(value: 0)
            var received: Result<[String], UnderlayDNSResolutionError>?
            AsyncUnderlayDNSResolver(lookup: lookup).resolve(
                host: host, timeout: timeout, callbackQueue: callbackQueue
            ) {
                received = $0
                done.signal()
            }
            precondition(done.wait(timeout: .now() + 3) == .success)
            switch (received!, expected) {
            case (.success(let actual), .success(let wanted)):
                precondition(actual == wanted)
            case (.failure(let actual), .failure(let wanted)):
                precondition(actual == wanted)
            default: preconditionFailure("Unexpected resolver response")
            }
        }
        assertResult(lookup: { _ in ["203.0.113.42", "2001:db8::1"] },
                     expected: .success(["203.0.113.42", "2001:db8::1"]))
        assertResult(lookup: { _ in [] }, expected: .failure(.noAddresses))
        assertResult(lookup: { _ in throw UnderlayDNSResolutionError.lookupFailed },
                     expected: .failure(.lookupFailed))
        assertResult(lookup: { _ in [] }, timeout: 0, expected: .failure(.timedOut))
        assertResult(lookup: { _ in preconditionFailure("Unbounded DNS lookup executed") },
                     host: String(repeating: "a", count: 254),
                     expected: .failure(.lookupFailed))
        assertResult(lookup: { _ in preconditionFailure("NUL DNS lookup executed") },
                     host: "good.example\\0evil.example",
                     expected: .failure(.lookupFailed))

        let gate = DispatchSemaphore(value: 0)
        let blockedWorker = DispatchSemaphore(value: 0)
        let resolver = AsyncUnderlayDNSResolver(lookup: { _ in
            blockedWorker.wait()
            return ["203.0.113.42"]
        })
        var errors: [UnderlayDNSResolutionError] = []
        resolver.resolve(host: "slow.test", timeout: 0.05, callbackQueue: callbackQueue) {
            if case .failure(let e) = $0 { errors.append(e) }
            gate.signal()
        }
        precondition(gate.wait(timeout: .now() + 2) == .success)
        precondition(errors == [.timedOut])
        resolver.resolve(host: "second.test", timeout: 1, callbackQueue: callbackQueue) {
            if case .failure(let e) = $0 { errors.append(e) }
            gate.signal()
        }
        precondition(gate.wait(timeout: .now() + 2) == .success)
        precondition(errors == [.timedOut, .busy])
        blockedWorker.signal()
        precondition(gate.wait(timeout: .now() + .milliseconds(150)) == .timedOut,
                     "Timed-out DNS completion was called twice")
        print("Async DNS pre-route: success, empty/error, timeout, busy and once-only passed")
    }
}

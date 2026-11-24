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
                     host: "good.example\0evil.example",
                     expected: .failure(.lookupFailed))
        // Final DNS preflight must reject hostile hosts independently of
        // the profile parser without ever calling libc or injected lookup.
        for unsafeHost in [
            "home.example.test\n", "home\t.example.test", "home example.test",
            "home.example.test\u{0085}", "fe80::1%en0",
            "[2001:db8::1]", "home.example.test\u{007F}"
        ] {
            assertResult(
                lookup: { _ in preconditionFailure("Unsafe DNS lookup executed") },
                host: unsafeHost, expected: .failure(.lookupFailed)
            )
        }
        assertResult(
            lookup: { host in
                precondition(host == "2001:db8::1")
                return ["2001:db8::1"]
            },
            host: "2001:db8::1", expected: .success(["2001:db8::1"])
        )

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
        // Cancellation silences an obsolete startup callback WITHOUT
        // releasing a still-blocked getaddrinfo worker for another request.
        let cancelEntered = DispatchSemaphore(value: 0)
        let cancelWorkerRelease = DispatchSemaphore(value: 0)
        let canceledDelivered = DispatchSemaphore(value: 0)
        let canceledResolver = AsyncUnderlayDNSResolver(lookup: { _ in
            cancelEntered.signal()
            cancelWorkerRelease.wait()
            return ["203.0.113.42"]
        })
        let stale = canceledResolver.resolve(
            host: "stale.test", timeout: 1, callbackQueue: callbackQueue
        ) { _ in canceledDelivered.signal() }
        precondition(cancelEntered.wait(timeout: .now() + 2) == .success)
        stale.cancel()
        stale.cancel() // idempotent, safe even after the worker returns
        let busyDone = DispatchSemaphore(value: 0)
        canceledResolver.resolve(
            host: "must-still-be-busy.test", timeout: 1, callbackQueue: callbackQueue
        ) { result in
            guard case .failure(.busy) = result else {
                preconditionFailure("Canceled DNS released blocked worker")
            }
            busyDone.signal()
        }
        precondition(busyDone.wait(timeout: .now() + 2) == .success)
        cancelWorkerRelease.signal()
        precondition(canceledDelivered.wait(timeout: .now() + .milliseconds(200)) == .timedOut)

        // Suppress callback even when an invalid-host completion has been
        // queued but the destination serial callback queue is paused.
        let queuedCallback = DispatchQueue(label: "underlay-dns-cancel-queued")
        let queueBlocked = DispatchSemaphore(value: 0)
        let unblockQueue = DispatchSemaphore(value: 0)
        queuedCallback.async {
            queueBlocked.signal()
            unblockQueue.wait()
        }
        precondition(queueBlocked.wait(timeout: .now() + 2) == .success)
        let canceledInvalidResult = DispatchSemaphore(value: 0)
        let invalid = AsyncUnderlayDNSResolver(
            lookup: { _ in preconditionFailure("Invalid host reached DNS lookup") }
        ).resolve(
            host: "invalid\n.example", callbackQueue: queuedCallback
        ) { _ in canceledInvalidResult.signal() }
        invalid.cancel()
        unblockQueue.signal()
        let queueDrained = DispatchSemaphore(value: 0)
        queuedCallback.async { queueDrained.signal() }
        precondition(queueDrained.wait(timeout: .now() + 2) == .success)
        precondition(canceledInvalidResult.wait(timeout: .now()) == .timedOut)

        // Timeout scheduled on callbackQueue must also respect cancellation.
        let canceledTimeout = DispatchSemaphore(value: 0)
        let invalidDeadline = AsyncUnderlayDNSResolver(
            lookup: { _ in preconditionFailure("Zero deadline started DNS worker") }
        ).resolve(
            host: "no-time.test", timeout: 0, callbackQueue: callbackQueue
        ) { _ in canceledTimeout.signal() }
        invalidDeadline.cancel()
        let callbacksDrained = DispatchSemaphore(value: 0)
        callbackQueue.async { callbacksDrained.signal() }
        precondition(callbacksDrained.wait(timeout: .now() + 2) == .success)
        precondition(canceledTimeout.wait(timeout: .now()) == .timedOut)

        // Every failure is a fixed, redacted DNS error: the Rust codec
        // has not yet been allocated on any of these startup paths.
        let expectedDescriptions: [(UnderlayDNSResolutionError, String)] = [
            (.busy, "A previous VPN DNS lookup is still running; reconnect after it finishes."),
            (.timedOut, "VPN server DNS lookup timed out; check connectivity and reconnect."),
            (.noAddresses, "VPN server DNS lookup returned no usable IP addresses."),
            (.lookupFailed, "Unable to resolve the VPN server address; check DNS and reconnect.")
        ]
        var uniqueDescriptions = Set<String>()
        for (failure, message) in expectedDescriptions {
            precondition(failure.errorDescription == message)
            precondition(failure.localizedDescription == message)
            precondition(!message.contains("home.example.test"))
            precondition(!message.contains("Rust"))
            uniqueDescriptions.insert(message)
        }
        precondition(uniqueDescriptions.count == 4)
        print("Async DNS pre-route: success, empty/error, timeout, busy, once-only, cancellation and redacted diagnostics passed")
    }
}

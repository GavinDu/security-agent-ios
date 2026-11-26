import Foundation

@main
struct ProviderLifecycleSmoke {
    static func main() {
        var state = PacketTunnelProviderState()
        precondition(state.phase == .idle)
        precondition(state.beginStart())
        precondition(!state.beginStart())
        precondition(state.finishStart(success: true))
        precondition(state.phase == .connected)
        precondition(state.beginStop())
        precondition(!state.beginStop())
        precondition(!state.finishStart(success: true))
        precondition(state.finishStop())
        precondition(state.phase == .idle)
        precondition(!state.finishStop())

        precondition(state.beginStart())
        precondition(state.beginStop()) // stop while awaiting Rust handshake
        precondition(!state.finishStart(success: false))
        precondition(state.finishStop())
        precondition(state.beginStart())
        precondition(state.finishStart(success: false)) // failed handshake
        precondition(state.phase == .idle)
        precondition(!state.beginStop())
        for _ in 0..<1024 {
            precondition(state.beginStart())
            precondition(state.finishStart(success: true))
            precondition(state.beginStop())
            precondition(state.finishStop())
        }
        // A duplicate or reentrant callback cannot deliver the OS result twice.
        var results: [Int] = []
        var once: PacketTunnelOneShot<Int>!
        once = PacketTunnelOneShot { value in
            results.append(value)
            once.call(99)
        }
        once.call(1)
        once.call(2)
        precondition(results == [1])
        let lock = NSLock()
        var count = 0
        let concurrent = PacketTunnelOneShot<Int> { _ in
            lock.lock()
            count += 1
            lock.unlock()
        }
        DispatchQueue.concurrentPerform(iterations: 128) { concurrent.call($0) }
        precondition(count == 1)

        // Real provider ownership logic with fake transports; a stop can
        // acknowledge before start, and an old stop must not drain new waiters.
        final class Engine {}
        enum Failure: Error { case stopped, denied }
        var ownership = PacketTunnelProviderOwnership<Engine>()
        var starts = 0
        var stops = 0
        let old = Engine()
        let new = Engine()
        let firstStart = PacketTunnelOneShot<Error?> { error in
            precondition(error != nil)
            starts += 1
        }
        precondition(ownership.beginStart(firstStart))
        ownership.installEngine(old)
        precondition(ownership.beginStop { stops += 1 })
        precondition(!ownership.beginStop { stops += 1 })
        precondition(!ownership.finishStart(for: old, success: true))
        precondition(ownership.takeStopCallbacks().stops.isEmpty)
        precondition(ownership.finishStop(for: old))
        let callbacks = ownership.takeStopCallbacks()
        callbacks.start?.call(Failure.stopped)
        callbacks.stops.forEach { $0() }
        firstStart.call(nil)
        precondition(starts == 1 && stops == 2)
        let nextStart = PacketTunnelOneShot<Error?> { error in
            precondition(error == nil)
            starts += 1
        }
        precondition(ownership.beginStart(nextStart))
        ownership.installEngine(new)
        precondition(ownership.finishStart(for: new, success: true))
        nextStart.call(nil)
        precondition(ownership.beginStop { stops += 1 })
        precondition(!ownership.finishStop(for: old))
        precondition(ownership.takeStopCallbacks().stops.isEmpty)
        precondition(ownership.finishStop(for: new))
        ownership.takeStopCallbacks().stops.forEach { $0() }
        precondition(starts == 2 && stops == 3 && ownership.phase == .idle)
        let denied = PacketTunnelOneShot<Error?> { error in
            precondition(error != nil)
            starts += 1
        }
        precondition(ownership.beginStart(denied))
        ownership.failPreparation()
        denied.call(Failure.denied)
        precondition(ownership.phase == .idle && ownership.engine == nil)
        precondition(starts == 3)
        print("Provider lifecycle: serialized start/stop, late callbacks, repeated stop and 1024 cycles passed")
    }
}

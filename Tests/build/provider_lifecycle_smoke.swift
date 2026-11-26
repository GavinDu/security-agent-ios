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
        print("Provider lifecycle: serialized start/stop, late callbacks, repeated stop and 1024 cycles passed")
    }
}

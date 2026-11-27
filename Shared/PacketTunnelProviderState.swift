import Foundation

/// Queue-confined provider lifecycle state; all transitions occur on the
/// PacketTunnelProvider private serial dispatch queue.
struct PacketTunnelProviderState {
    enum Phase: Equatable { case idle, starting, connected, stopping }

    private(set) var phase: Phase = .idle

    mutating func beginStart() -> Bool {
        guard phase == .idle else { return false }
        phase = .starting
        return true
    }

    /// Returns false for a late start callback after stop was requested.
    mutating func finishStart(success: Bool) -> Bool {
        guard phase == .starting else { return false }
        phase = success ? .connected : .idle
        return true
    }

    /// Only the first stop request may initiate transport teardown.
    mutating func beginStop() -> Bool {
        guard phase == .starting || phase == .connected else { return false }
        phase = .stopping
        return true
    }

    @discardableResult
    mutating func finishStop() -> Bool {
        guard phase == .stopping else { return false }
        phase = .idle
        return true
    }
}

/// Independent provider-to-OS completion boundary. A transport callback may
/// be obsolete, duplicated or delivered concurrently with provider release.
/// Consume the callback before invoking it and never hold the lock across
/// user code (which may reenter the provider).
final class PacketTunnelOneShot<Value> {
    private let lock = NSLock()
    private var completion: ((Value) -> Void)?

    init(_ completion: @escaping (Value) -> Void) {
        self.completion = completion
    }

    func call(_ value: Value) {
        lock.lock()
        let callback = completion
        completion = nil
        lock.unlock()
        callback?(value)
    }
}


/// Production provider ownership, independent of Apple's extension host.
/// All calls are serialized by the owning provider's lifecycle queue.
/// The same object is exercised with fake engine identities in native tests.
struct PacketTunnelProviderOwnership<Engine: AnyObject> {
    private var lifecycle = PacketTunnelProviderState()
    private(set) var engine: Engine?
    private var pendingStart: PacketTunnelOneShot<Error?>?
    private var stopWaiters: [() -> Void] = []

    var phase: PacketTunnelProviderState.Phase { lifecycle.phase }

    mutating func beginStart(_ completion: PacketTunnelOneShot<Error?>) -> Bool {
        guard lifecycle.beginStart() else { return false }
        pendingStart = completion
        return true
    }

    // Called only by the accepted start on the same queue, after validation.
    mutating func installEngine(_ transport: Engine) {
        engine = transport
    }

    mutating func failPreparation() {
        guard lifecycle.finishStart(success: false) else { return }
        pendingStart = nil
    }

    mutating func finishStart(for transport: Engine, success: Bool) -> Bool {
        guard engine === transport, lifecycle.finishStart(success: success) else { return false }
        pendingStart = nil
        if !success { engine = nil }
        return true
    }

    mutating func beginStop(_ completion: @escaping () -> Void) -> Bool {
        stopWaiters.append(completion)
        return lifecycle.beginStop()
    }

    mutating func finishStop(for transport: Engine?) -> Bool {
        guard engine === transport, lifecycle.finishStop() else { return false }
        engine = nil
        return true
    }

    /// Only drain after teardown is acknowledged or the provider is idle.
    /// Return closures to the caller; invoke them outside mutable ownership.
    mutating func takeStopCallbacks() -> (start: PacketTunnelOneShot<Error?>?, stops: [() -> Void]) {
        guard lifecycle.phase == .idle else { return (nil, []) }
        let callbacks = (pendingStart, stopWaiters)
        pendingStart = nil
        stopWaiters.removeAll()
        return callbacks
    }
}

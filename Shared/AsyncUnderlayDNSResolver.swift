import Foundation
#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif

/// Single-flight DNS preflight for the encrypted UDP underlay. A blocking
/// getaddrinfo call never runs on the serial BoringTun engine queue.
/// A timed-out worker stays busy until it actually returns, so repeated
/// attempts fail closed rather than spawn an unbounded number of threads.
enum UnderlayDNSResolutionError: Error, Equatable, LocalizedError {
    case busy
    case timedOut
    case noAddresses
    case lookupFailed

    /// Deliberately redacted: a DNS failure is not a Rust codec error,
    /// and exposing the private peer hostname or libc text is unnecessary.
    var errorDescription: String? {
        switch self {
        case .busy:
            return "A previous VPN DNS lookup is still running; reconnect after it finishes."
        case .timedOut:
            return "VPN server DNS lookup timed out; check connectivity and reconnect."
        case .noAddresses:
            return "VPN server DNS lookup returned no usable IP addresses."
        case .lookupFailed:
            return "Unable to resolve the VPN server address; check DNS and reconnect."
        }
    }
}

/// Cancellation suppresses an obsolete startup callback; it cannot stop
/// getaddrinfo or free the singleton resolver's occupied worker.
final class UnderlayDNSCancellation {
    private let lock = NSLock()
    private var cancelled = false

    func cancel() {
        lock.lock()
        cancelled = true
        lock.unlock()
    }

    var isCancelled: Bool {
        lock.lock()
        defer { lock.unlock() }
        return cancelled
    }
}

final class AsyncUnderlayDNSResolver {
    // One resolver for the entire PacketTunnel extension process, not one per
    // restarted BoringTunTransport. A blocked old getaddrinfo must not leave
    // a growing number of worker threads after repeated tunnel restarts.
    static let shared = AsyncUnderlayDNSResolver()

    typealias Lookup = (String) throws -> [String]

    // DNS is on VPN startup's critical path. The worker remains single-flight
    // and OS getaddrinfo cannot be cancelled, but avoid utility-QoS starvation.
    private let worker = DispatchQueue(label: "com.gavindu.securityagent.underlay-dns", qos: .userInitiated)
    private let lock = NSLock()
    private var lookupInFlight = false
    private let lookup: Lookup

    init(lookup: @escaping Lookup = SystemUnderlayAddressLookup.lookup) {
        self.lookup = lookup
    }

    @discardableResult
    func resolve(
        host: String,
        timeout: TimeInterval = 5,
        callbackQueue: DispatchQueue,
        completion: @escaping (Result<[String], UnderlayDNSResolutionError>) -> Void
    ) -> UnderlayDNSCancellation {
        let cancellation = UnderlayDNSCancellation()
        guard timeout > 0, timeout.isFinite else {
            callbackQueue.async {
                if !cancellation.isCancelled { completion(.failure(.timedOut)) }
            }
            return cancellation
        }
        // Enforce the final pre-getaddrinfo input boundary even if an
        // upstream ServerProfile validator is accidentally bypassed.
        // Numeric IPv6 here is unbracketed; interface zone IDs are unsafe.
        guard !host.isEmpty, host.utf8.count <= 253,
              !host.unicodeScalars.contains(where: {
                  CharacterSet.controlCharacters.contains($0) ||
                  CharacterSet.whitespacesAndNewlines.contains($0)
              }),
              !host.contains("%"), !host.contains("["),
              !host.contains("]") else {
            callbackQueue.async {
                if !cancellation.isCancelled { completion(.failure(.lookupFailed)) }
            }
            return cancellation
        }
        lock.lock()
        if lookupInFlight {
            lock.unlock()
            callbackQueue.async {
                if !cancellation.isCancelled { completion(.failure(.busy)) }
            }
            return cancellation
        }
        lookupInFlight = true
        lock.unlock()

        // One absolute monotonic deadline, independent of the transport
        // queue. A delayed callback must not install routes using an
        // already-expired DNS preflight even if the worker returned first.
        let deadline = DispatchTime.now() + timeout
        let once = UnderlayDNSOnce(
            callbackQueue: callbackQueue, cancellation: cancellation,
            deadline: deadline, completion: completion
        )
        DispatchQueue.global(qos: .userInitiated).asyncAfter(deadline: deadline) {
            once.finish(.failure(.timedOut))
        }
        worker.async { [self] in
            let result: Result<[String], UnderlayDNSResolutionError>
            do {
                let resolved = try lookup(host)
                result = resolved.isEmpty ? .failure(.noAddresses) : .success(resolved)
            } catch {
                result = .failure(.lookupFailed)
            }
            lock.lock()
            lookupInFlight = false
            lock.unlock()
            once.finish(result)
        }
        return cancellation
    }
}

private final class UnderlayDNSOnce {
    private let lock = NSLock()
    private var finished = false
    private let callbackQueue: DispatchQueue
    private let cancellation: UnderlayDNSCancellation
    private let deadline: DispatchTime
    private let completion: (Result<[String], UnderlayDNSResolutionError>) -> Void

    init(
        callbackQueue: DispatchQueue,
        cancellation: UnderlayDNSCancellation,
        deadline: DispatchTime,
        completion: @escaping (Result<[String], UnderlayDNSResolutionError>) -> Void
    ) {
        self.callbackQueue = callbackQueue
        self.cancellation = cancellation
        self.deadline = deadline
        self.completion = completion
    }

    func finish(_ result: Result<[String], UnderlayDNSResolutionError>) {
        lock.lock()
        guard !finished else { lock.unlock(); return }
        finished = true
        lock.unlock()
        // Check at callback execution, not just when it is scheduled:
        // teardown may cancel after worker return but before queue delivery.
        callbackQueue.async { [completion, cancellation, deadline] in
            guard !cancellation.isCancelled else { return }
            // Dispatch scheduling is not a real-time guarantee. Recheck
            // at delivery before any transport-side allocation or routes.
            if DispatchTime.now() >= deadline {
                completion(.failure(.timedOut))
            } else {
                completion(result)
            }
        }
    }
}

/// Return only numeric sockaddr results, never a hostname for a second DNS
/// lookup after the NetworkExtension inner routing has been installed.
enum SystemUnderlayAddressLookup {
    static func lookup(_ host: String) throws -> [String] {
        var hints = addrinfo()
        hints.ai_family = AF_UNSPEC
        #if canImport(Glibc)
        hints.ai_socktype = Int32(SOCK_DGRAM.rawValue)
        #else
        hints.ai_socktype = SOCK_DGRAM
        #endif
        hints.ai_protocol = Int32(IPPROTO_UDP)
        var first: UnsafeMutablePointer<addrinfo>?
        guard getaddrinfo(host, nil, &hints, &first) == 0, let head = first else {
            if let first { freeaddrinfo(first) }
            throw UnderlayDNSResolutionError.lookupFailed
        }
        defer { freeaddrinfo(head) }
        var candidates: [String] = []
        var current: UnsafeMutablePointer<addrinfo>? = head
        while let record = current {
            defer { current = record.pointee.ai_next }
            guard record.pointee.ai_family == AF_INET ||
                    record.pointee.ai_family == AF_INET6 else { continue }
            guard let socketAddress = record.pointee.ai_addr,
                  record.pointee.ai_addrlen > 0 else {
                throw UnderlayDNSResolutionError.lookupFailed
            }
            var numeric = [CChar](repeating: 0, count: Int(NI_MAXHOST))
            let rc = getnameinfo(
                socketAddress, record.pointee.ai_addrlen,
                &numeric, socklen_t(numeric.count), nil, 0, NI_NUMERICHOST
            )
            guard rc == 0 else { throw UnderlayDNSResolutionError.lookupFailed }
            candidates.append(String(cString: numeric))
            guard candidates.count <= 32 else { throw UnderlayDNSResolutionError.lookupFailed }
        }
        return candidates
    }
}

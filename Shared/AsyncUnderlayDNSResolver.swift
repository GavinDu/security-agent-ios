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
enum UnderlayDNSResolutionError: Error, Equatable {
    case busy
    case timedOut
    case noAddresses
    case lookupFailed
}

final class AsyncUnderlayDNSResolver {
    // One resolver for the entire PacketTunnel extension process, not one per
    // restarted BoringTunTransport. A blocked old getaddrinfo must not leave
    // a growing number of worker threads after repeated tunnel restarts.
    static let shared = AsyncUnderlayDNSResolver()

    typealias Lookup = (String) throws -> [String]

    private let worker = DispatchQueue(label: "com.gavindu.securityagent.underlay-dns", qos: .utility)
    private let lock = NSLock()
    private var lookupInFlight = false
    private let lookup: Lookup

    init(lookup: @escaping Lookup = SystemUnderlayAddressLookup.lookup) {
        self.lookup = lookup
    }

    func resolve(
        host: String,
        timeout: TimeInterval = 5,
        callbackQueue: DispatchQueue,
        completion: @escaping (Result<[String], UnderlayDNSResolutionError>) -> Void
    ) {
        guard timeout > 0, timeout.isFinite else {
            callbackQueue.async { completion(.failure(.timedOut)) }
            return
        }
        // Never pass unbounded or NUL-terminated/truncated user input to C.
        guard !host.isEmpty, host.utf8.count <= 253, !host.contains("\0") else {
            callbackQueue.async { completion(.failure(.lookupFailed)) }
            return
        }
        lock.lock()
        if lookupInFlight {
            lock.unlock()
            callbackQueue.async { completion(.failure(.busy)) }
            return
        }
        lookupInFlight = true
        lock.unlock()

        let once = UnderlayDNSOnce(callbackQueue: callbackQueue, completion: completion)
        callbackQueue.asyncAfter(deadline: .now() + timeout) {
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
    }
}

private final class UnderlayDNSOnce {
    private let lock = NSLock()
    private var finished = false
    private let callbackQueue: DispatchQueue
    private let completion: (Result<[String], UnderlayDNSResolutionError>) -> Void

    init(
        callbackQueue: DispatchQueue,
        completion: @escaping (Result<[String], UnderlayDNSResolutionError>) -> Void
    ) {
        self.callbackQueue = callbackQueue
        self.completion = completion
    }

    func finish(_ result: Result<[String], UnderlayDNSResolutionError>) {
        lock.lock()
        guard !finished else { lock.unlock(); return }
        finished = true
        lock.unlock()
        callbackQueue.async { [completion] in completion(result) }
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

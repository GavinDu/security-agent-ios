import Foundation

@main
struct ImmutableIdentityInstallerSmoke {
    enum FakeError: Error { case denied }

    static func main() throws {
        let first = Data(repeating: 0x35, count: 32)
        let second = Data(repeating: 0x67, count: 32)

        let created = try ImmutableIdentityInstaller.install(
            candidate: first,
            insertIfAbsent: { value in
                precondition(value == first)
                return .inserted
            },
            readExisting: { preconditionFailure("Fresh insert cannot reread") }
        )
        precondition(created == first)

        let adopted = try ImmutableIdentityInstaller.install(
            candidate: second,
            insertIfAbsent: { _ in .alreadyExists },
            readExisting: { first }
        )
        precondition(adopted == first && adopted != second,
                     "Duplicate insert must adopt the Keychain winner")

        func requiresFailure(_ action: () throws -> Data) {
            do {
                _ = try action()
                preconditionFailure("Unsafe identity creation succeeded")
            } catch {}
        }
        requiresFailure {
            try ImmutableIdentityInstaller.install(
                candidate: Data(repeating: 0, count: 31),
                insertIfAbsent: { _ in preconditionFailure("invalid candidate inserted") },
                readExisting: { nil }
            )
        }
        requiresFailure {
            try ImmutableIdentityInstaller.install(
                candidate: second,
                insertIfAbsent: { _ in .alreadyExists },
                readExisting: { nil }
            )
        }
        requiresFailure {
            try ImmutableIdentityInstaller.install(
                candidate: second,
                insertIfAbsent: { _ in .alreadyExists },
                readExisting: { Data(repeating: 0x55, count: 31) }
            )
        }
        requiresFailure {
            try ImmutableIdentityInstaller.install(
                candidate: second,
                insertIfAbsent: { _ in throw FakeError.denied },
                readExisting: { preconditionFailure("insert failure cannot reread") }
            )
        }

        final class AtomicFakeKeychain {
            private let lock = NSLock()
            private var stored: Data?
            func create(_ candidate: Data) throws -> Data {
                try ImmutableIdentityInstaller.install(
                    candidate: candidate,
                    insertIfAbsent: { value in
                        lock.lock()
                        defer { lock.unlock() }
                        guard stored == nil else { return .alreadyExists }
                        stored = value
                        return .inserted
                    },
                    readExisting: {
                        lock.lock()
                        defer { lock.unlock() }
                        return stored
                    }
                )
            }
        }
        let keychain = AtomicFakeKeychain()
        let resultsLock = NSLock()
        var values: [Data] = []
        var failures = 0
        DispatchQueue.concurrentPerform(iterations: 64) { i in
            do {
                let candidate = Data(repeating: UInt8(i + 1), count: 32)
                let value = try keychain.create(candidate)
                resultsLock.lock()
                values.append(value)
                resultsLock.unlock()
            } catch {
                resultsLock.lock()
                failures += 1
                resultsLock.unlock()
            }
        }
        precondition(failures == 0 && values.count == 64)
        guard let winner = values.first else { preconditionFailure("No identity") }
        precondition(values.allSatisfy { $0 == winner },
                     "Concurrent creation must never rotate identity")
        print("Immutable WireGuard identity: duplicate, denial, malformed and concurrent insert passed")
    }
}

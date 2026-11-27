import Foundation

@main
struct IdentityRotationStageSmoke {
    static func main() throws {
        func key(_ n: UInt8) -> String { Data(repeating: n, count: 32).base64EncodedString() }
        // Deterministic fake derivation isolates the store/transaction policy.
        // CryptoKit derivation is exercised by native XCTest.
        func derive(_ data: Data) -> String { data.base64EncodedString() }
        let binding = IdentityRotationStagePolicy.Binding(transactionID: UUID(),
            serverPublicKey: key(42), activePublicKey: key(3))
        var stored: Data?
        var inserts = 0
        func stage(_ request: IdentityRotationStagePolicy.Binding) throws -> IdentityRotationStagePolicy.Receipt {
            try IdentityRotationStagePolicy.stage(binding: request, readActivePublicKey: { key(3) },
                readStage: { stored }, generateCandidate: { Data(repeating: 7, count: 32) },
                derivePublicKey: derive, insertIfAbsent: { bytes in inserts += 1; stored = bytes; return .inserted })
        }
        let first = try stage(binding)
        let retry = try stage(binding)
        precondition(first == retry && inserts == 1 && first.candidatePublicKey == key(7))
        do {
            _ = try stage(.init(transactionID: UUID(), serverPublicKey: key(42), activePublicKey: key(3)))
            preconditionFailure("different transaction adopted")
        } catch IdentityRotationStagePolicy.StageError.conflict {}
        stored = Data("corrupt".utf8)
        do { _ = try stage(binding); preconditionFailure("corrupt stage adopted") }
        catch IdentityRotationStagePolicy.StageError.invalidRecord {}
        precondition(inserts == 1)
        do {
            _ = try IdentityRotationStagePolicy.stage(binding: binding, readActivePublicKey: { key(3) },
                readStage: { nil }, generateCandidate: { Data(repeating: 3, count: 32) },
                derivePublicKey: derive, insertIfAbsent: { _ in preconditionFailure("same identity inserted") })
            preconditionFailure("same identity accepted")
        } catch IdentityRotationStagePolicy.StageError.invalidRecord {}
        stored = nil
        var current = key(3)
        do {
            _ = try IdentityRotationStagePolicy.stage(binding: binding, readActivePublicKey: { current },
                readStage: { stored }, generateCandidate: { Data(repeating: 7, count: 32) },
                derivePublicKey: derive, insertIfAbsent: { bytes in
                    stored = bytes; current = key(11); return .inserted
                })
            preconditionFailure("stale active key received a receipt")
        } catch IdentityRotationStagePolicy.StageError.activeChanged {}
        precondition(stored != nil)
        print("Identity rotation insert-only staging and binding policy passed")
    }
}

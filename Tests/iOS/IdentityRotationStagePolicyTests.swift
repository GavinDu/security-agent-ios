import Foundation
import XCTest
import CryptoKit
@testable import AgentApp

final class IdentityRotationStagePolicyTests: XCTestCase {
    private func key(_ n: UInt8) -> String { Data(repeating: n, count: 32).base64EncodedString() }
    private func derive(_ data: Data) throws -> String {
        try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: data)
            .publicKey.rawRepresentation.base64EncodedString()
    }

    func testInsertOnlyRetryAndDifferentTransactionConflict() throws {
        let active = try derive(Data(repeating: 3, count: 32))
        let binding = IdentityRotationStagePolicy.Binding(transactionID: UUID(),
            serverPublicKey: key(42), activePublicKey: active)
        let candidate = Data(repeating: 7, count: 32)
        var stored: Data?
        var inserts = 0
        func stage(_ request: IdentityRotationStagePolicy.Binding) throws -> IdentityRotationStagePolicy.Receipt {
            try IdentityRotationStagePolicy.stage(binding: request, readActivePublicKey: { active },
                readStage: { stored }, generateCandidate: { candidate }, derivePublicKey: derive,
                insertIfAbsent: { bytes in inserts += 1; stored = bytes; return .inserted })
        }
        let receipt = try stage(binding)
        XCTAssertEqual(receipt.candidatePublicKey, try derive(candidate))
        XCTAssertEqual(try stage(binding), receipt)
        XCTAssertEqual(inserts, 1)
        XCTAssertThrowsError(try stage(.init(transactionID: UUID(),
            serverPublicKey: binding.serverPublicKey, activePublicKey: active)))
        XCTAssertEqual(inserts, 1)
        stored = Data("corrupt".utf8)
        XCTAssertThrowsError(try stage(binding))
        XCTAssertEqual(inserts, 1)
    }

    func testDuplicateRaceReturnsPersistedWinnerAndActiveChangeBlocks() throws {
        let active = try derive(Data(repeating: 3, count: 32))
        let binding = IdentityRotationStagePolicy.Binding(transactionID: UUID(),
            serverPublicKey: key(42), activePublicKey: active)
        var winner: Data?
        let prior = try IdentityRotationStagePolicy.stage(binding: binding, readActivePublicKey: { active },
            readStage: { winner }, generateCandidate: { Data(repeating: 7, count: 32) },
            derivePublicKey: derive, insertIfAbsent: { winner = $0; return .inserted })
        var visible: Data?
        let retried = try IdentityRotationStagePolicy.stage(binding: binding, readActivePublicKey: { active },
            readStage: { visible }, generateCandidate: { Data(repeating: 11, count: 32) },
            derivePublicKey: derive, insertIfAbsent: { _ in visible = winner; return .alreadyExists })
        XCTAssertEqual(prior, retried)
        XCTAssertThrowsError(try IdentityRotationStagePolicy.stage(binding: binding,
            readActivePublicKey: { self.key(9) }, readStage: { visible },
            generateCandidate: { XCTFail("generated after active change"); return Data() },
            derivePublicKey: derive, insertIfAbsent: { _ in XCTFail("inserted"); return .inserted }))
    }

    func testSameDerivedPublicKeyAndMissingReadbackFailClosed() throws {
        let activeSecret = Data(repeating: 3, count: 32)
        let active = try derive(activeSecret)
        let binding = IdentityRotationStagePolicy.Binding(transactionID: UUID(),
            serverPublicKey: key(42), activePublicKey: active)
        XCTAssertThrowsError(try IdentityRotationStagePolicy.stage(binding: binding,
            readActivePublicKey: { active }, readStage: { nil }, generateCandidate: { activeSecret },
            derivePublicKey: derive, insertIfAbsent: { _ in XCTFail("same identity staged"); return .inserted }))
        XCTAssertThrowsError(try IdentityRotationStagePolicy.stage(binding: binding,
            readActivePublicKey: { active }, readStage: { nil },
            generateCandidate: { Data(repeating: 7, count: 32) },
            derivePublicKey: derive, insertIfAbsent: { _ in .inserted }))
    }

    func testActiveChangeAfterInsertRetainsCandidateAndBlocksReceipt() throws {
        let active = try derive(Data(repeating: 3, count: 32))
        let replacement = try derive(Data(repeating: 11, count: 32))
        let binding = IdentityRotationStagePolicy.Binding(transactionID: UUID(),
            serverPublicKey: key(42), activePublicKey: active)
        var stored: Data?
        var current = active
        XCTAssertThrowsError(try IdentityRotationStagePolicy.stage(binding: binding,
            readActivePublicKey: { current }, readStage: { stored },
            generateCandidate: { Data(repeating: 7, count: 32) }, derivePublicKey: derive,
            insertIfAbsent: { bytes in stored = bytes; current = replacement; return .inserted })) {
                XCTAssertEqual($0 as? IdentityRotationStagePolicy.StageError, .activeChanged)
            }
        XCTAssertNotNil(stored)
        XCTAssertThrowsError(try IdentityRotationStagePolicy.stage(binding: binding,
            readActivePublicKey: { current }, readStage: { stored },
            generateCandidate: { XCTFail("generated after active change"); return Data() },
            derivePublicKey: derive, insertIfAbsent: { _ in XCTFail("overwrote stage"); return .inserted }))
    }

    func testDerivedPublicKeyMustMatchStoredSecretAndUnknownFieldsRejected() throws {
        let active = try derive(Data(repeating: 3, count: 32))
        let binding = IdentityRotationStagePolicy.Binding(transactionID: UUID(),
            serverPublicKey: key(42), activePublicKey: active)
        var stored: Data?
        func stage() throws -> IdentityRotationStagePolicy.Receipt {
            try IdentityRotationStagePolicy.stage(binding: binding, readActivePublicKey: { active },
                readStage: { stored }, generateCandidate: { Data(repeating: 7, count: 32) },
                derivePublicKey: derive, insertIfAbsent: { stored = $0; return .inserted })
        }
        _ = try stage()
        var object = try XCTUnwrap(JSONSerialization.jsonObject(with: XCTUnwrap(stored)) as? [String: Any])
        object["candidatePrivateKey"] = Data(repeating: 11, count: 32).base64EncodedString()
        stored = try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
        XCTAssertThrowsError(try stage())
        object["candidatePrivateKey"] = Data(repeating: 7, count: 32).base64EncodedString()
        object["unexpected"] = true
        stored = try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
        XCTAssertThrowsError(try stage())
    }
}

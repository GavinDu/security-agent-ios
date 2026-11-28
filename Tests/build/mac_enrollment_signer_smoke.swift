import Foundation
import CryptoKit

@main struct MacEnrollmentSignerSmoke {
    static func main() throws {
        typealias P = MacEnrollmentSignerPolicy
        let server = Data(repeating: 42, count: 32).base64EncodedString()
        let other = Data(repeating: 43, count: 32).base64EncodedString()
        var verified = server
        var stored: Data?
        var writes = 0
        var generations = 0
        let seed = Data(repeating: 7, count: 32)
        func commission() throws -> P.PublicIdentity {
            try P.commission(server: server, readVerifiedServer: { verified },
                readRecord: { stored }, insertIfAbsent: { writes += 1; stored = $0 },
                generateSeed: { generations += 1; return seed })
        }
        func expectFailure(_ expected: P.Failure, _ run: () throws -> Void) {
            do { try run(); fatalError("expected refusal") }
            catch let error as P.Failure { precondition(error == expected) }
            catch { fatalError("unexpected failure") }
        }
        let first = try commission()
        let again = try commission()
        precondition(first == again && writes == 1 && generations == 1)
        let publicKey = try Curve25519.Signing.PrivateKey(rawRepresentation: seed).publicKey.rawRepresentation
        precondition(first.signingPublicKey == publicKey)
        let saved = stored
        let loaded = try P.existing(server: server, expectedSigner: publicKey,
            readVerifiedServer: { verified }, readRecord: { stored })
        precondition(loaded == first)
        expectFailure(.conflictingSigner) {
            _ = try P.existing(server: server, expectedSigner: Data(repeating: 1, count: 32),
                readVerifiedServer: { verified }, readRecord: { stored })
        }
        verified = other
        expectFailure(.serverChanged) { _ = try commission() }
        verified = server
        stored = Data([1])
        expectFailure(.invalidRecord) { _ = try commission() }
        precondition(writes == 1 && generations == 1)
        stored = nil
        expectFailure(.missingSigner) {
            _ = try P.existing(server: server, expectedSigner: publicKey,
                readVerifiedServer: { verified }, readRecord: { stored })
        }
        expectFailure(.missingReadback) {
            _ = try P.commission(server: server, readVerifiedServer: { verified },
                readRecord: { nil }, insertIfAbsent: { _ in }, generateSeed: { seed })
        }
        // A racing explicit commission must adopt the stored winner.
        let race = try P.commission(server: server, readVerifiedServer: { verified },
            readRecord: { stored }, insertIfAbsent: { _ in stored = saved },
            generateSeed: { Data(repeating: 8, count: 32) })
        precondition(race == first)
        expectFailure(.invalidRecord) {
            _ = try P.existing(server: other, expectedSigner: publicKey,
                readVerifiedServer: { other }, readRecord: { saved })
        }
        stored = nil
        expectFailure(.invalidRecord) {
            _ = try P.commission(server: server, readVerifiedServer: { verified },
                readRecord: { stored }, insertIfAbsent: { _ in fatalError("invalid seed written") },
                generateSeed: { Data(repeating: 0, count: 32) })
        }
        expectFailure(.serverChanged) {
            _ = try P.commission(server: server, readVerifiedServer: { verified },
                readRecord: { stored }, insertIfAbsent: { stored = $0; verified = other },
                generateSeed: { seed })
        }
        precondition(stored != nil)
        print("Mac enrollment signer custody policy passed")
    }
}

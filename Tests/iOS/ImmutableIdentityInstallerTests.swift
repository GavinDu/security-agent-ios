import Foundation
import XCTest
@testable import AgentApp

final class ImmutableIdentityInstallerTests: XCTestCase {
    private enum FakeError: Error { case denied }

    func testFreshInsertReturnsGeneratedSecretWithoutSecondRead() throws {
        let proposed = Data(repeating: 0x11, count: 32)
        var reread = false
        let result = try ImmutableIdentityInstaller.install(
            candidate: proposed,
            insertIfAbsent: { _ in .inserted },
            readExisting: { reread = true; return nil }
        )
        XCTAssertEqual(result, proposed)
        XCTAssertFalse(reread)
    }

    func testConcurrentDuplicateReturnsExistingWinnerNotProposedKey() throws {
        let stored = Data(repeating: 0x12, count: 32)
        let losingCandidate = Data(repeating: 0x22, count: 32)
        let result = try ImmutableIdentityInstaller.install(
            candidate: losingCandidate,
            insertIfAbsent: { _ in .alreadyExists },
            readExisting: { stored }
        )
        XCTAssertEqual(result, stored)
        XCTAssertNotEqual(result, losingCandidate)
    }

    func testMissingOrCorruptWinnerFailsClosed() {
        let candidate = Data(repeating: 0x55, count: 32)
        XCTAssertThrowsError(try ImmutableIdentityInstaller.install(
            candidate: candidate,
            insertIfAbsent: { _ in .alreadyExists },
            readExisting: { nil }
        ))
        XCTAssertThrowsError(try ImmutableIdentityInstaller.install(
            candidate: candidate,
            insertIfAbsent: { _ in .alreadyExists },
            readExisting: { Data(repeating: 0x01, count: 31) }
        ))
    }

    func testInvalidCandidateAndKeychainInsertionErrorFailClosed() {
        XCTAssertThrowsError(try ImmutableIdentityInstaller.install(
            candidate: Data(repeating: 0x01, count: 31),
            insertIfAbsent: { _ in XCTFail("Invalid candidate inserted"); return .inserted },
            readExisting: { nil }
        ))
        XCTAssertThrowsError(try ImmutableIdentityInstaller.install(
            candidate: Data(repeating: 0x01, count: 32),
            insertIfAbsent: { _ in throw FakeError.denied },
            readExisting: { XCTFail("Denied insert triggered read"); return nil }
        ))
    }
}

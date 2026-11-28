import Foundation
import XCTest
@testable import AgentApp

final class MacPeerOwnerRequestFrameTests: XCTestCase {
    func testNativeFrameMatchesSharedGoldenVectorsAndRejectsBadInputs() throws {
        let request = UUID(uuidString: "01020304-0506-0708-090A-0B0C0D0E0F10")!
        let generation = UUID(uuidString: "11121314-1516-1718-191A-1B1C1D1E1F20")!
        let epoch = UUID(uuidString: "21222324-2526-2728-292A-2B2C2D2E2F30")!
        let zero = UUID(uuidString: "00000000-0000-0000-0000-000000000000")!
        let server = Data((49...80).map { UInt8($0) }).base64EncodedString()
        let client = Data((81...112).map { UInt8($0) }).base64EncodedString()
        let revision: UInt64 = 0x8123456789abcdef
        func encode(_ op: MacPeerOwnerRequestFrame.Operation = .enroll,
                    requestID: UUID? = nil, daemonGeneration: UUID? = nil,
                    rosterEpoch: UUID? = nil, expectedRevision: UInt64? = nil,
                    serverKey: String? = nil, clientKey: String? = nil) -> Data? {
            MacPeerOwnerRequestFrame.encode(requestID: requestID ?? request, daemonGeneration: daemonGeneration ?? generation,
                rosterEpoch: rosterEpoch ?? epoch, expectedRevision: expectedRevision ?? revision,
                serverPublicKey: serverKey ?? server, clientPublicKey: clientKey ?? client, operation: op)
        }
        // Identical to Tests/build/peer_owner_request_vectors.hex; Linux
        // Swift and Rust consume that shared fixture directly.
        let vectors = ["5341504f010100000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f308123456789abcdef3132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f7000", "5341504f010200000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f308123456789abcdef3132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f70fe"]
        let operations: [MacPeerOwnerRequestFrame.Operation] = [.enroll, .revoke(slot: 254)]
        for (index, op) in operations.enumerated() {
            let bytes = try XCTUnwrap(encode(op))
            XCTAssertEqual(bytes.count, 129)
            XCTAssertEqual(bytes.map { String(format: "%02x", Int($0)) }.joined(), vectors[index])
        }
        XCTAssertNil(encode(requestID: zero))
        XCTAssertNil(encode(daemonGeneration: zero))
        XCTAssertNil(encode(rosterEpoch: zero))
        XCTAssertNil(encode(expectedRevision: UInt64.max))
        XCTAssertNil(encode(clientKey: server))
        XCTAssertNil(encode(clientKey: "invalid"))
        XCTAssertNil(encode(serverKey: Data(repeating: 0, count: 32).base64EncodedString()))
        for slot in [UInt8(0), 1, 255] { XCTAssertNil(encode(.revoke(slot: slot))) }
    }
}

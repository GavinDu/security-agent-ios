import Foundation
import XCTest
@testable import AgentApp

final class NativeVPNManagerInventoryTests: XCTestCase {
    private struct NativeStub {
        let id: Int
        let providerID: String
    }

    func testEmptyOrUnrelatedInventoryHasNoSelectedManager() {
        let other = NativeStub(id: 1, providerID: "com.example.other")
        let expected = AgentConstants.tunnelBundleID
        for values in [[NativeStub](), [other]] {
            switch NativeVPNManagerInventory.select(
                from: values, matching: { $0.providerID == expected }
            ) {
            case .none: break
            default: XCTFail("Did not reject empty or unrelated inventory")
            }
        }
    }

    func testUniqueMatchingManagerDoesNotSelectForeignManager() {
        let expected = AgentConstants.tunnelBundleID
        let selected = NativeStub(id: 2, providerID: expected)
        let foreign = NativeStub(id: 1, providerID: "com.example.other")
        switch NativeVPNManagerInventory.select(
            from: [foreign, selected], matching: { $0.providerID == expected }
        ) {
        case .one(let manager): XCTAssertEqual(manager.id, 2)
        default: XCTFail("Did not select the unique matching manager")
        }
    }

    func testMultipleMatchingManagersFailClosedRegardlessOfOrder() {
        let expected = AgentConstants.tunnelBundleID
        let a = NativeStub(id: 2, providerID: expected)
        let b = NativeStub(id: 3, providerID: expected)
        for values in [[a, b], [b, a]] {
            switch NativeVPNManagerInventory.select(
                from: values, matching: { $0.providerID == expected }
            ) {
            case .duplicate: break
            default: XCTFail("Ambiguous native VPN inventory was accepted")
            }
        }
    }
}

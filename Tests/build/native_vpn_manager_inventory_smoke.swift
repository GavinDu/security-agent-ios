import Foundation

@main
struct NativeVPNManagerInventorySmoke {
    private struct FakeManager {
        let identifier: String
        let nativeID: Int
    }

    static func main() {
        let expected = "com.gavindu.securityagent.ios.PacketTunnel"
        let foreign = FakeManager(identifier: "com.example.unrelated", nativeID: 101)
        let first = FakeManager(identifier: expected, nativeID: 201)
        let second = FakeManager(identifier: expected, nativeID: 202)
        let predicate: (FakeManager) -> Bool = { $0.identifier == expected }

        switch NativeVPNManagerInventory.select(from: [], matching: predicate) {
        case .none: break
        default: preconditionFailure("Empty inventory must not select a manager")
        }
        switch NativeVPNManagerInventory.select(from: [foreign], matching: predicate) {
        case .none: break
        default: preconditionFailure("Unrelated manager must be ignored")
        }
        switch NativeVPNManagerInventory.select(
            from: [foreign, first, foreign], matching: predicate
        ) {
        case .one(let selected):
            precondition(selected.nativeID == 201)
        default: preconditionFailure("Unique matching manager must be selected")
        }
        for inventory in [[first, second], [foreign, second, first],
                          [first, foreign, second], [second, first]] {
            switch NativeVPNManagerInventory.select(from: inventory, matching: predicate) {
            case .duplicate: break
            default: preconditionFailure("Duplicate target managers were not rejected")
            }
        }
        print("Native VPN manager inventory: none, one, unrelated and ambiguous all passed")
    }
}

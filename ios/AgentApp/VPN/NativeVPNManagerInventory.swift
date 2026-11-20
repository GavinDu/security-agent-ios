import Foundation

/// Pure, deterministic inventory decision. Do not select an arbitrary first
/// NETunnelProviderManager when more than one targets this extension.
enum NativeVPNManagerSelection<Value> {
    case none
    case one(Value)
    case duplicate
}

enum NativeVPNManagerInventory {
    static func select<Value>(
        from values: [Value],
        matching predicate: (Value) -> Bool
    ) -> NativeVPNManagerSelection<Value> {
        var selected: Value?
        for value in values where predicate(value) {
            if selected != nil { return .duplicate }
            selected = value
        }
        if let selected { return .one(selected) }
        return .none
    }
}

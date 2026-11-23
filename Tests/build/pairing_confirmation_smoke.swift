private struct TestMacProfile: Equatable {
    var publicKey: String
    var endpoint: String
    var routeMode: String
    var onDemand: Bool
}

@main
struct PairingConfirmationSmoke {
    static func main() {
        let original = TestMacProfile(
            publicKey: "mac-a", endpoint: "home.example:51820",
            routeMode: "split", onDemand: false
        )
        var gate = PairingConfirmationGate<TestMacProfile>()
        precondition(!gate.permitsSave(original))
        gate.setConfirmed(true, for: nil)
        precondition(!gate.permitsSave(original))
        gate.setConfirmed(true, for: original)
        precondition(gate.permitsSave(original))
        precondition(!gate.permitsSave(nil))
        precondition(!gate.permitsSave(TestMacProfile(
            publicKey: "mac-b", endpoint: original.endpoint,
            routeMode: "split", onDemand: false
        )))
        precondition(!gate.permitsSave(TestMacProfile(
            publicKey: original.publicKey, endpoint: "evil.example:51820",
            routeMode: "split", onDemand: false
        )))
        precondition(!gate.permitsSave(TestMacProfile(
            publicKey: original.publicKey, endpoint: original.endpoint,
            routeMode: "full", onDemand: false
        )))
        precondition(!gate.permitsSave(TestMacProfile(
            publicKey: original.publicKey, endpoint: original.endpoint,
            routeMode: "split", onDemand: true
        )))
        let changed = TestMacProfile(
            publicKey: "mac-b", endpoint: original.endpoint,
            routeMode: "split", onDemand: false
        )
        gate.setConfirmed(true, for: changed)
        precondition(gate.permitsSave(changed))
        precondition(!gate.permitsSave(original))
        gate.setConfirmed(false, for: changed)
        precondition(!gate.permitsSave(changed))
        gate.setConfirmed(true, for: original)
        gate.reset()
        precondition(!gate.permitsSave(original))
        print("Pairing confirmation exact-snapshot gate passed")
    }
}

import Foundation

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
        let generation = UUID()
        let peer = MacPeerConfirmationContext(serverPublicKey: "mac-a", endpoint: "home.example:51820", clientPublicKey: "phone-a", generation: generation)
        var macGate = PairingConfirmationGate<MacPeerConfirmationContext>()
        macGate.setConfirmed(true, for: peer)
        precondition(macGate.permitsSave(peer))
        precondition(!macGate.permitsSave(MacPeerConfirmationContext(serverPublicKey: "mac-b", endpoint: peer.endpoint, clientPublicKey: peer.clientPublicKey, generation: generation)))
        precondition(!macGate.permitsSave(MacPeerConfirmationContext(serverPublicKey: peer.serverPublicKey, endpoint: "other.example:51820", clientPublicKey: peer.clientPublicKey, generation: generation)))
        precondition(!macGate.permitsSave(MacPeerConfirmationContext(serverPublicKey: peer.serverPublicKey, endpoint: peer.endpoint, clientPublicKey: "phone-b", generation: generation)))
        precondition(!macGate.permitsSave(MacPeerConfirmationContext(serverPublicKey: peer.serverPublicKey, endpoint: peer.endpoint, clientPublicKey: peer.clientPublicKey, generation: UUID())))
        macGate.reset()
        precondition(!macGate.permitsSave(peer))
        print("Pairing confirmation exact-snapshot gate passed")
    }
}

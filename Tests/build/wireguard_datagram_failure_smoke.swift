import Foundation

@main
struct WireGuardDatagramFailureSmoke {
    static func main() {
        typealias P = WireGuardDatagramFailurePolicy
        precondition(P.disposition(for: .malformedIncomingPacket) == .discard)
        precondition(P.disposition(for: .authenticationRejected) == .discard)
        precondition(P.disposition(for: .malformedFFIResponse) == .stopTunnel)
        precondition(P.disposition(for: .unexpectedLocalFailure) == .stopTunnel)
        print("WireGuard datagram error classification passed")
    }
}

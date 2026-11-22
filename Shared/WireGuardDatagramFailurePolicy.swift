import Foundation

/// Only unauthenticated remote datagram rejection is nonfatal. Unexpected
/// local FFI or lifecycle failures must stop the Rust BoringTun session.
enum WireGuardDatagramFailurePolicy {
    enum Reason: Equatable {
        case malformedIncomingPacket
        case authenticationRejected
        case malformedFFIResponse
        case unexpectedLocalFailure
    }

    enum Disposition: Equatable {
        case discard
        case stopTunnel
    }

    static func disposition(for reason: Reason) -> Disposition {
        switch reason {
        case .malformedIncomingPacket, .authenticationRejected:
            return .discard
        case .malformedFFIResponse, .unexpectedLocalFailure:
            return .stopTunnel
        }
    }
}

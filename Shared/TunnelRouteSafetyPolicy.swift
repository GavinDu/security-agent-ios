import Foundation

/// Fail closed while the full-tunnel encrypted UDP underlay and IPv4/IPv6
/// kill-switch behavior have no signed-device verification (issues #65/#29).
/// An App UI preference is not a security boundary; PacketTunnel enforces
/// this check before any default IPv4 or IPv6 route is installed.
enum TunnelRouteSafetyPolicy {
    static func permitsStart(_ mode: RouteMode) -> Bool {
        switch mode {
        case .split: return true
        case .full: return false
        }
    }
}

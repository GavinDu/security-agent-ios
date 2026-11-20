import Foundation

// Stub only the model shape that the production Foundation-only policy uses.
// The policy itself is exactly the shared source imported by both iOS targets.
enum RouteMode { case split, full }

@main
struct TunnelRouteSafetySmoke {
    static func main() {
        precondition(TunnelRouteSafetyPolicy.permitsStart(.split))
        precondition(!TunnelRouteSafetyPolicy.permitsStart(.full))
        for _ in 0..<1_024 {
            precondition(TunnelRouteSafetyPolicy.permitsStart(.split))
            precondition(!TunnelRouteSafetyPolicy.permitsStart(.full))
        }
        print("Full-tunnel disabled by default; split route remains available")
    }
}

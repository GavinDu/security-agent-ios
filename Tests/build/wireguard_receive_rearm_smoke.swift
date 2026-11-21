import Foundation

@main
struct WireGuardReceiveRearmSmoke {
    static func main() {
        precondition(WireGuardReceiveRearmPolicy.emptyReceiveDelayMilliseconds == 25)
        precondition(WireGuardReceiveRearmPolicy.needsBackoff(receivedByteCount: nil))
        precondition(WireGuardReceiveRearmPolicy.needsBackoff(receivedByteCount: 0))
        precondition(WireGuardReceiveRearmPolicy.needsBackoff(receivedByteCount: -1))
        for positive in [1, 4, 32, 65600] {
            precondition(!WireGuardReceiveRearmPolicy.needsBackoff(receivedByteCount: positive))
        }
        print("UDP empty/no-data receive rearm backoff policy passed")
    }
}

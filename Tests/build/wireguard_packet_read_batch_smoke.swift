import Foundation

@main
struct WireGuardPacketReadBatchSmoke {
    static func main() {
        let accepts = WireGuardPacketReadBatchPolicy.accepts
        precondition(accepts(0, 0), "An empty read is valid and should back off")
        precondition(accepts(1, 1))
        precondition(accepts(256, 256))
        precondition(!accepts(0, 1))
        precondition(!accepts(1, 0))
        precondition(!accepts(2, 1), "Never truncate with zip")
        precondition(!accepts(1, 2), "Never truncate extra protocol values")
        precondition(!accepts(-1, -1))
        precondition(!accepts(-1, 1))
        precondition(!accepts(Int.max, Int.max - 1))
        precondition(accepts(Int.max, Int.max))
        print("BoringTun native packetFlow read batch count gate passed")
    }
}

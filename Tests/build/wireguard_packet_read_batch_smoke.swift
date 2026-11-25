import Foundation

@main
struct WireGuardPacketReadBatchSmoke {
    static func main() {
        let accepts = WireGuardPacketReadBatchPolicy.accepts
        let lengths = WireGuardPacketReadBatchPolicy.acceptsPayloadLengths
        precondition(WireGuardPacketReadBatchPolicy.maxPacketBytes == IPPacketEnvelope.maxInnerBytes)
        precondition(lengths([IPPacketEnvelope.maxInnerBytes]))
        precondition(!lengths([IPPacketEnvelope.maxInnerBytes + 1]))
        precondition(accepts(0, 0), "Empty callbacks remain legal; empty-rearm backoff applies")
        precondition(accepts(1, 1))
        precondition(accepts(256, 256))
        precondition(!accepts(257, 257), "Oversized matched callback must fail closed")
        precondition(!accepts(Int.max, Int.max), "Int.max equal counts are not safe")
        precondition(!accepts(0, 1))
        precondition(!accepts(1, 0))
        precondition(!accepts(2, 1), "Never truncate with zip")
        precondition(!accepts(1, 2), "Never truncate extra protocol values")
        precondition(!accepts(-1, -1))
        precondition(!accepts(-1, 1))
        precondition(!accepts(Int.max, Int.max - 1))

        precondition(lengths([]), "Empty native batch does not contain invalid payloads")
        precondition(lengths([20, 1420, 65_536]))
        precondition(lengths(Array(repeating: 1420, count: 256)))
        precondition(lengths(Array(repeating: 65_536, count: 128)),
                     "Exact eight-MiB boundary permitted")
        precondition(!lengths(Array(repeating: 65_536, count: 129)),
                     "Aggregate payload over budget must fail closed")
        precondition(!lengths(Array(repeating: 1, count: 257)),
                     "Excessive count fails even with small payloads")
        for hostile in [[0], [-1], [65_537], [Int.max], [1, Int.max],
                        [65_536, -1]] {
            precondition(!lengths(hostile), "Invalid local packet size permitted")
        }
        print("BoringTun native packetFlow count, byte-budget, and overflow gates passed")
    }
}

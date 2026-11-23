import Foundation

@main
struct SharedProfileReadbackSmoke {
    static func main() {
        let exact = Data(repeating: 0x31, count: 128)
        precondition(SharedProfileReadbackPolicy.accepts(expected: exact, observed: exact))
        precondition(!SharedProfileReadbackPolicy.accepts(expected: exact, observed: nil))
        var altered = exact
        altered[20] = 0x32
        precondition(!SharedProfileReadbackPolicy.accepts(expected: exact, observed: altered))
        precondition(!SharedProfileReadbackPolicy.accepts(expected: exact, observed: exact.dropLast()))
        precondition(!SharedProfileReadbackPolicy.accepts(expected: Data(), observed: Data()))
        precondition(!SharedProfileReadbackPolicy.accepts(
            expected: Data(repeating: 0x30, count: SharedProfileDataPolicy.maxEncodedBytes + 1),
            observed: Data(repeating: 0x30, count: SharedProfileDataPolicy.maxEncodedBytes + 1)
        ))
        let upper = Data(repeating: 0x31, count: SharedProfileDataPolicy.maxEncodedBytes)
        precondition(SharedProfileReadbackPolicy.accepts(expected: upper, observed: upper))
        print("Exact bounded App Group public profile save/readback policy passed")
    }
}

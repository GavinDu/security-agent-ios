import Foundation

@main
struct ResolvedUnderlayCandidateSmoke {
    static func main() {
        let routes = ["10.8.0.0/24"]
        func choice(_ addresses: [String], routes override: [String]? = nil) -> String? {
            ResolvedUnderlayCandidatePolicy.selectPinnedAddress(
                addresses, includedIPv4CIDRs: override ?? routes
            )
        }
        precondition(choice(["203.0.113.42"]) == "203.0.113.42")
        precondition(choice(["2001:db8::1"]) == "2001:db8::1")
        precondition(choice(["203.0.113.42", "2001:db8::1"]) == "203.0.113.42")
        precondition(choice(["2001:db8::1", "203.0.113.42"]) == "2001:db8::1")
        precondition(choice(["203.0.113.42", "203.0.113.42"]) == "203.0.113.42")
        precondition(choice(["::ffff:10.8.1.1"]) == "::ffff:10.8.1.1")
        for forbidden in [
            "10.8.0.0", "10.8.0.1", "10.8.0.255", "::ffff:10.8.0.1",
            "::ffff:a08:1", "0x0a080001", "10.8.0.001", "10.8.0.256",
            "home.example.net", "203.0.113.42:51820", "[2001:db8::1]",
            "fe80::1%en0", "203.0.113.42 ", "", "2001:db8::oops"
        ] {
            precondition(choice([forbidden]) == nil, "Unsafe candidate: \(forbidden)")
            precondition(choice(["203.0.113.42", forbidden]) == nil)
            precondition(choice([forbidden, "203.0.113.42"]) == nil)
        }
        precondition(choice([]) == nil)
        precondition(choice(["203.0.113.42"], routes: []) == nil)
        precondition(choice(["203.0.113.42"], routes: ["not-a-cidr"]) == nil)
        precondition(choice(["203.0.113.42"], routes: ["0.0.0.0/0"]) == nil)
        print("DNS-resolved numeric underlay candidate fail-closed policy passed")
    }
}

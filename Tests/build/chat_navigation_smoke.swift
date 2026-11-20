import Foundation

// The production policy is compiled with this test-only server-address stub;
// it does not import the rest of the app or any NetworkExtension entitlement.
enum AgentConstants { static let serverIPv4 = "10.8.0.1" }

@main
struct ChatNavigationSmoke {
    static func main() {
        let allowed = [
            "http://10.8.0.1:8080/chat",
            "http://10.8.0.1:8080/static/app.js?v=1",
            "http://10.8.0.1:8080/chat#messages"
        ]
        let rejected = [
            "https://10.8.0.1:8080/chat",
            "http://10.8.0.1/chat",
            "http://10.8.0.1:8081/chat",
            "http://10.8.0.2:8080/chat",
            "http://10.8.0.1.evil.example:8080/chat",
            "http://user:password@10.8.0.1:8080/chat",
            "http://10.8.0.1:8080@evil.example/chat",
            "http://example.com:8080/chat",
            "about:blank",
            "data:text/html,spoof",
            "file:///private/var/mobile/Containers/Data/chat.html"
        ]
        for address in allowed {
            guard let url = URL(string: address) else { preconditionFailure("Bad test URL") }
            precondition(AgentChatNavigationPolicy.allows(url), "Unexpected denial: \(address)")
        }
        for address in rejected {
            guard let url = URL(string: address) else { preconditionFailure("Bad test URL") }
            precondition(!AgentChatNavigationPolicy.allows(url), "Unsafe navigation: \(address)")
        }
        print("Private chat origin: three valid and 11 adversarial URLs passed")
    }
}

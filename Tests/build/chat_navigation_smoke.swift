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
        // Main-frame origin alone is insufficient: nested same-origin frames
        // and nil targetFrame popups must not create extra documents.
        let chat = URL(string: "http://10.8.0.1:8080/chat")!
        let external = URL(string: "https://example.org/private")!
        precondition(AgentChatNavigationPolicy.allowsDocumentNavigation(
            chat, isMainFrame: true
        ))
        precondition(!AgentChatNavigationPolicy.allowsDocumentNavigation(
            chat, isMainFrame: false
        ), "Same-origin subframe/popup must be blocked")
        precondition(!AgentChatNavigationPolicy.allowsDocumentNavigation(
            external, isMainFrame: true
        ), "Cross-origin top-level document must be blocked")
        for address in rejected {
            let url = URL(string: address)!
            precondition(!AgentChatNavigationPolicy.allowsDocumentNavigation(
                url, isMainFrame: true
            ), "Unsafe top-level URL: \(address)")
        }
        // A resource path on the same trusted origin is NOT a trusted
        // top-level document; only canonical /chat paths can host chat.
        let acceptedDocuments = [
            "http://10.8.0.1:8080/chat",
            "http://10.8.0.1:8080/chat/",
            "http://10.8.0.1:8080/chat/thread-123",
            "http://10.8.0.1:8080/chat/thread_123/",
            "http://10.8.0.1:8080/chat?thread=123#reply"
        ]
        let rejectedDocuments = [
            "http://10.8.0.1:8080/admin",
            "http://10.8.0.1:8080/status",
            "http://10.8.0.1:8080/static/app.js?v=1",
            "http://10.8.0.1:8080/chat-admin",
            "http://10.8.0.1:8080/chat//admin",
            "http://10.8.0.1:8080/chat/thread//admin",
            "http://10.8.0.1:8080/chat/../admin",
            "http://10.8.0.1:8080/chat/%2e%2e/admin",
            "http://10.8.0.1:8080/chat%2fadmin",
            "http://10.8.0.1:8080/chat/%5cadmin"
        ]
        for address in acceptedDocuments {
            precondition(AgentChatNavigationPolicy.allowsDocumentNavigation(
                URL(string: address)!, isMainFrame: true
            ), "Legitimate chat document refused: \(address)")
        }
        for address in rejectedDocuments {
            precondition(!AgentChatNavigationPolicy.allowsDocumentNavigation(
                URL(string: address)!, isMainFrame: true
            ), "Non-chat top-level document accepted: \(address)")
        }
        // Origin policy for JS/CSS/XHR subresources is intentionally unchanged.
        precondition(AgentChatNavigationPolicy.allows(
            URL(string: "http://10.8.0.1:8080/static/app.js")!
        ))
        print("Private chat origin and frame isolation: 3 valid, 11 adversarial URLs passed")
    }
}

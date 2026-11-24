import Foundation
import XCTest
@testable import AgentApp

final class AgentChatNavigationPolicyTests: XCTestCase {
    func testAllowsOnlyPrivateAgentHTTPOrigin() {
        let accepted = [
            "http://10.8.0.1:8080/chat",
            "http://10.8.0.1:8080/static/chat.css?v=1",
            "http://10.8.0.1:8080/chat#messages"
        ]
        for address in accepted {
            let url = URL(string: address)!
            XCTAssertTrue(AgentChatNavigationPolicy.allows(url), address)
        }
    }

    func testMainFrameOnlyNavigation() {
        let chat = URL(string: "http://10.8.0.1:8080/chat")!
        let alternatePath = URL(string: "http://10.8.0.1:8080/static/app.js")!
        let external = URL(string: "https://example.org/chat")!
        XCTAssertTrue(AgentChatNavigationPolicy.allowsDocumentNavigation(
            chat, isMainFrame: true
        ))
        for target in [chat, alternatePath] {
            XCTAssertFalse(AgentChatNavigationPolicy.allowsDocumentNavigation(
                target, isMainFrame: false
            ), "Block nested/popup documents, including same-origin")
        }
        XCTAssertFalse(AgentChatNavigationPolicy.allowsDocumentNavigation(
            external, isMainFrame: true
        ))
    }

    func testOnlyCanonicalChatPathsBecomeTopLevelDocuments() {
        let allowed = [
            "http://10.8.0.1:8080/chat",
            "http://10.8.0.1:8080/chat/",
            "http://10.8.0.1:8080/chat/thread-123",
            "http://10.8.0.1:8080/chat/thread_456/",
            "http://10.8.0.1:8080/chat?thread=9#reply"
        ]
        for address in allowed {
            XCTAssertTrue(AgentChatNavigationPolicy.allowsDocumentNavigation(
                URL(string: address)!, isMainFrame: true
            ), address)
        }
        let rejected = [
            "http://10.8.0.1:8080/admin",
            "http://10.8.0.1:8080/status",
            "http://10.8.0.1:8080/static/app.js",
            "http://10.8.0.1:8080/chat-admin",
            "http://10.8.0.1:8080/chat//admin",
            "http://10.8.0.1:8080/chat/%2e%2e/admin",
            "http://10.8.0.1:8080/chat%2fadmin",
            "http://10.8.0.1:8080/chat/%5cadmin"
        ]
        for address in rejected {
            XCTAssertFalse(AgentChatNavigationPolicy.allowsDocumentNavigation(
                URL(string: address)!, isMainFrame: true
            ), address)
        }
        XCTAssertTrue(AgentChatNavigationPolicy.allows(
            URL(string: "http://10.8.0.1:8080/static/app.js")!
        ), "Subresource origin policy must remain unaffected")
    }

    func testRejectsSchemeAuthorityAndPortVariants() {
        let rejected = [
            "https://10.8.0.1:8080/chat",
            "http://10.8.0.1/chat",
            "http://10.8.0.1:8081/chat",
            "http://10.8.0.2:8080/chat",
            "http://10.8.0.1.evil.example:8080/chat",
            "http://user:secret@10.8.0.1:8080/chat",
            "http://10.8.0.1:8080@evil.example/chat",
            "http://example.com:8080/chat",
            "about:blank",
            "about:srcdoc",
            "data:text/html,spoof",
            "file:///private/var/mobile/Containers/Data/chat.html"
        ]
        for address in rejected {
            guard let url = URL(string: address) else {
                XCTFail("Bad test URL: \(address)")
                continue
            }
            XCTAssertFalse(AgentChatNavigationPolicy.allows(url), address)
        }
    }
}

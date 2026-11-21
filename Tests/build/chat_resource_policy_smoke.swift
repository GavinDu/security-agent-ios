import Foundation

// Compile the actual production resource-policy generator with this isolated
// server-address stub; the WebKit installation is tested by iOS XCTest.
enum AgentConstants { static let serverIPv4 = "10.8.0.1" }

@main
struct ChatResourcePolicySmoke {
    static func main() throws {
        let encoded = try AgentChatResourcePolicy.encodedRules()
        let decoded = try JSONSerialization.jsonObject(with: Data(encoded.utf8))
        guard let rules = decoded as? [[String: [String: String]]] else {
            preconditionFailure("Malformed WebKit JSON resource rule list")
        }
        precondition(rules.count == 4)
        let patterns = rules.map { $0["trigger"]!["url-filter"]! }
        let actions = rules.map { $0["action"]!["type"]! }
        precondition(actions == ["block", "block", "ignore-previous-rules", "ignore-previous-rules"])

        let regex = try patterns.map { try NSRegularExpression(pattern: $0) }
        func permitted(_ url: String) -> Bool {
            var blocked = false
            for (index, pattern) in regex.enumerated() {
                let range = NSRange(url.startIndex..<url.endIndex, in: url)
                guard pattern.firstMatch(in: url, range: range) != nil else { continue }
                if actions[index] == "block" { blocked = true }
                if actions[index] == "ignore-previous-rules" { blocked = false }
            }
            return !blocked
        }
        for url in [
            "http://10.8.0.1:8080/chat",
            "http://10.8.0.1:8080/static/app.js?v=1",
            "ws://10.8.0.1:8080/chat/stream"
        ] {
            precondition(permitted(url), "Private resource rejected: \(url)")
        }
        for url in [
            "https://cdn.example.com/script.js",
            "http://external.example.com/image.png",
            "https://10.8.0.1:8080/chat",
            "wss://10.8.0.1:8080/chat/stream",
            "ws://example.com/socket",
            "http://10.8.0.1:8081/chat",
            "http://10.8.0.11:8080/chat",
            "http://10.8.0.1.evil.example:8080/chat",
            "http://10.8.0.1:8080@evil.example/chat"
        ] {
            precondition(!permitted(url), "External resource escaped filter: \(url)")
        }
        print("WebKit chat resource allowlist: 3 private + 9 hostile URLs passed (4 rules)")
    }
}

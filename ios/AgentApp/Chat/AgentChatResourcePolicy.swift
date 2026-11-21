import Foundation

/// WebKit document navigation does NOT govern every script/image/fetch/WS
/// subresource. Install these resource rules before opening the private chat.
/// Keep URL authority literal and path-delimited: no external host can match.
enum AgentChatResourcePolicy {
    enum PolicyError: Error {
        case invalidEncoding
    }

    static let identifier = "com.gavindu.securityagent.chat-resources-v1"

    static func encodedRules() throws -> String {
        let host = NSRegularExpression.escapedPattern(for: AgentConstants.serverIPv4)
        // A blocking network rule followed only by exact, path-delimited
        // private HTTP and matching private WS exceptions. No broad HTTPS,
        // arbitrary domain, public CDN, or alternate port exception.
        let rules: [[String: Any]] = [
            [
                "trigger": ["url-filter": "^(http|https|ws|wss)://"],
                "action": ["type": "block"]
            ],
            [
                "trigger": ["url-filter": "^http://\\(host):8080(/|$)"],
                "action": ["type": "ignore-previous-rules"]
            ],
            [
                "trigger": ["url-filter": "^ws://\\(host):8080(/|$)"],
                "action": ["type": "ignore-previous-rules"]
            ]
        ]
        let bytes = try JSONSerialization.data(withJSONObject: rules, options: [.sortedKeys])
        guard let text = String(data: bytes, encoding: .utf8) else {
            throw PolicyError.invalidEncoding
        }
        return text
    }
}

import Foundation

/// Pure document-navigation allowlist for the VPN-private chat service.
/// The HTTP transport is deliberately limited to the fixed tunnel IPv4;
/// credentials and native bridge capabilities are never exposed to pages.
enum AgentChatNavigationPolicy {
    static func allows(_ url: URL) -> Bool {
        guard let components = URLComponents(url: url, resolvingAgainstBaseURL: false),
              components.scheme?.lowercased() == "http",
              components.host == AgentConstants.serverIPv4,
              components.port == 8080,
              components.user == nil, components.password == nil else {
            return false
        }
        return true
    }
}

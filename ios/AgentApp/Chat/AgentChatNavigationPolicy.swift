import Foundation

/// Pure document-navigation allowlist for the VPN-private chat service.
/// The HTTP transport is deliberately limited to the fixed tunnel IPv4;
/// credentials and native bridge capabilities are never exposed to pages.
enum AgentChatNavigationPolicy {
    /// Only the single trusted top-level chat document may navigate. Do not
    /// let nested iframes or new-window targets become extra document contexts.
    /// This is not a subresource firewall; #23 tracks network loads separately.
    static func allowsDocumentNavigation(_ url: URL, isMainFrame: Bool) -> Bool {
        guard isMainFrame else { return false }
        return allows(url)
    }

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

import Foundation

/// Pure document-navigation allowlist for the VPN-private chat service.
/// The HTTP transport is deliberately limited to the fixed tunnel IPv4;
/// credentials and native bridge capabilities are never exposed to pages.
enum AgentChatNavigationPolicy {
    /// Only the single trusted top-level chat document may navigate. Do not
    /// let nested iframes or new-window targets become extra document contexts.
    /// This is not a subresource firewall; #23 tracks network loads separately.
    static func allowsDocumentNavigation(_ url: URL, isMainFrame: Bool) -> Bool {
        guard isMainFrame, allows(url),
              let components = URLComponents(url: url, resolvingAgainstBaseURL: false) else {
            return false
        }
        // An exact private origin may also expose /admin or /status.
        // Navigation documents are limited to canonical /chat routes;
        // ordinary JS/CSS/image subresource allowlisting remains separate.
        return allowsChatDocumentPath(components.percentEncodedPath)
    }

    /// Reject encoded separators, traversal, and ambiguous normalization
    /// before WebKit requests a new top-level private-agent document.
    /// Chat thread route segments use conservative ASCII unreserved values;
    /// query and fragment navigation remain unrestricted on this origin.
    private static func allowsChatDocumentPath(_ rawPath: String) -> Bool {
        guard rawPath.utf8.count <= 1024 else { return false }
        if rawPath == "/chat" || rawPath == "/chat/" { return true }
        guard rawPath.hasPrefix("/chat/") else { return false }
        let descendant = rawPath.dropFirst("/chat/".count)
        let segments = descendant.split(separator: "/", omittingEmptySubsequences: false)
        guard !segments.isEmpty, segments.count <= 32 else { return false }
        for (index, segment) in segments.enumerated() {
            if segment.isEmpty {
                // A single trailing slash is allowed; repeated or interior
                // slashes are not canonical, including /chat//evil.
                guard index == segments.count - 1 else { return false }
                continue
            }
            guard segment.utf8.allSatisfy({ byte in
                (byte >= 65 && byte <= 90) ||  // A-Z
                (byte >= 97 && byte <= 122) || // a-z
                (byte >= 48 && byte <= 57) ||  // 0-9
                byte == 45 || byte == 95        // - _
            }) else { return false }
        }
        return true
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

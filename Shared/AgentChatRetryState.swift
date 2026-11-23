import Foundation

/// Keeps VPN-private WebKit load results bound to the exact page generation.
/// A dismissed/disconnected WKWebView must not re-publish stale failures.
struct AgentChatRetryState {
    private(set) var generation = UUID()
    private(set) var isUnavailable = false

    /// The web view's callback captures the generation that created it.
    /// Reports from a superseded view (even a late success) are ignored.
    @discardableResult
    mutating func reportLoadResult(unreachable: Bool, generation token: UUID) -> Bool {
        guard token == generation else { return false }
        isUnavailable = unreachable
        return true
    }

    /// A new identity forces SwiftUI to dismantle the old WKWebView and
    /// construct a fresh private data store when still VPN-connected.
    mutating func retry() {
        generation = UUID()
        isUnavailable = false
    }

    /// Called on every VPN state transition, including disconnect/reconnect.
    /// The view hierarchy still owns the VPN .connected-only gate.
    mutating func resetForVPNStatusChange() {
        retry()
    }
}

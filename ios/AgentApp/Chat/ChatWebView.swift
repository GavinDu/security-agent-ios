import SwiftUI
import WebKit

// Created only when the system VPN reports .connected; torn down on disconnect.
struct ChatWebView: UIViewRepresentable {
    let url: URL
    let onLoadState: (Bool) -> Void // false = chat loaded, true = unreachable

    func makeCoordinator() -> Coordinator { Coordinator(onLoadState: onLoadState) }

    /// Private agent chat must not retain cookies/cache/site storage on disk
    /// after a VPN disconnect or across application launches. This setting
    /// does not substitute for WebKit process teardown or origin filtering.
    static func makePrivateConfiguration() -> WKWebViewConfiguration {
        let configuration = WKWebViewConfiguration()
        configuration.websiteDataStore = .nonPersistent()
        configuration.defaultWebpagePreferences.allowsContentJavaScript = true
        return configuration
    }

    func makeUIView(context: Context) -> WKWebView {
        let configuration = Self.makePrivateConfiguration()
        let webView = WKWebView(frame: .zero, configuration: configuration)
        webView.navigationDelegate = context.coordinator
        webView.isInspectable = false
        // WKNavigationDelegate does not mediate all subresource loads.
        // Never fetch the private chat until a fail-closed WebKit resource
        // allowlist is compiled and installed into this view.
        let coordinator = context.coordinator
        do {
            let ruleSource = try AgentChatResourcePolicy.encodedRules()
            WKContentRuleListStore.default().compileContentRuleList(
                forIdentifier: AgentChatResourcePolicy.identifier,
                encodedContentRuleList: ruleSource
            ) { [weak webView] list, _ in
                DispatchQueue.main.async {
                    guard coordinator.isActive, let webView else { return }
                    guard let list else {
                        coordinator.onLoadState(true)
                        return
                    }
                    webView.configuration.userContentController.add(list)
                    webView.load(URLRequest(
                        url: url, cachePolicy: .reloadIgnoringLocalCacheData
                    ))
                }
            }
        } catch {
            coordinator.onLoadState(true)
        }
        return webView
    }

    func updateUIView(_ webView: WKWebView, context: Context) {}

    static func dismantleUIView(_ webView: WKWebView, coordinator: Coordinator) {
        coordinator.isActive = false
        webView.stopLoading()
        webView.navigationDelegate = nil
        webView.loadHTMLString("", baseURL: nil)
    }

    final class Coordinator: NSObject, WKNavigationDelegate {
        let onLoadState: (Bool) -> Void
        var isActive = true

        init(onLoadState: @escaping (Bool) -> Void) { self.onLoadState = onLoadState }

        /// WebKit may deliver a queued outcome after SwiftUI removes the
        /// VPN-gated view. Never publish that stale outcome into the current UI.
        /// SwiftUI dismantle and WKNavigationDelegate callbacks run on main.
        func reportLoadResult(_ unreachable: Bool) {
            guard isActive else { return }
            onLoadState(unreachable)
        }

        func webView(_ webView: WKWebView, didFinish navigation: WKNavigation!) {
            reportLoadResult(false)
        }

        func webView(_ webView: WKWebView, didFailProvisionalNavigation navigation: WKNavigation!,
                     withError error: Error) {
            reportLoadResult(true)
        }

        func webView(_ webView: WKWebView, didFail navigation: WKNavigation!,
                     withError error: Error) {
            reportLoadResult(true)
        }

        func webView(_ webView: WKWebView,
                     decidePolicyFor action: WKNavigationAction,
                     decisionHandler: @escaping (WKNavigationActionPolicy) -> Void) {
            guard isActive, let destination = action.request.url else {
                decisionHandler(.cancel)
                return
            }
            // Reject popup and nested document navigation, including same-origin frames.
            let isMainFrame = action.targetFrame?.isMainFrame == true
            decisionHandler(AgentChatNavigationPolicy.allowsDocumentNavigation(
                destination, isMainFrame: isMainFrame
            ) ? .allow : .cancel)
        }

        func webView(_ webView: WKWebView,
                     decidePolicyFor navigationResponse: WKNavigationResponse,
                     decisionHandler: @escaping (WKNavigationResponsePolicy) -> Void) {
            guard isActive, let destination = navigationResponse.response.url else {
                decisionHandler(.cancel)
                return
            }
            decisionHandler(AgentChatNavigationPolicy.allowsDocumentNavigation(
                destination, isMainFrame: navigationResponse.isForMainFrame
            ) ? .allow : .cancel)
        }
    }
}

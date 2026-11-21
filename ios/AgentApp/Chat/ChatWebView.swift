import SwiftUI
import WebKit

// Created only when the system VPN reports .connected; torn down on disconnect.
struct ChatWebView: UIViewRepresentable {
    let url: URL
    let onLoadState: (Bool) -> Void // false = chat loaded, true = unreachable

    func makeCoordinator() -> Coordinator { Coordinator(onLoadState: onLoadState) }

    func makeUIView(context: Context) -> WKWebView {
        let configuration = WKWebViewConfiguration()
        configuration.defaultWebpagePreferences.allowsContentJavaScript = true
        let webView = WKWebView(frame: .zero, configuration: configuration)
        webView.navigationDelegate = context.coordinator
        webView.isInspectable = false
        webView.load(URLRequest(url: url, cachePolicy: .reloadIgnoringLocalCacheData))
        return webView
    }

    func updateUIView(_ webView: WKWebView, context: Context) {}

    static func dismantleUIView(_ webView: WKWebView, coordinator: Coordinator) {
        webView.stopLoading()
        webView.navigationDelegate = nil
        webView.loadHTMLString("", baseURL: nil)
    }

    final class Coordinator: NSObject, WKNavigationDelegate {
        let onLoadState: (Bool) -> Void

        init(onLoadState: @escaping (Bool) -> Void) { self.onLoadState = onLoadState }

        func webView(_ webView: WKWebView, didFinish navigation: WKNavigation!) {
            onLoadState(false)
        }

        func webView(_ webView: WKWebView, didFailProvisionalNavigation navigation: WKNavigation!,
                     withError error: Error) {
            onLoadState(true)
        }

        func webView(_ webView: WKWebView, didFail navigation: WKNavigation!,
                     withError error: Error) {
            onLoadState(true)
        }

        func webView(_ webView: WKWebView,
                     decidePolicyFor action: WKNavigationAction,
                     decisionHandler: @escaping (WKNavigationActionPolicy) -> Void) {
            guard let destination = action.request.url else {
                decisionHandler(.cancel)
                return
            }
            // targetFrame == nil means a new-window/popup navigation. Reject
            // it rather than allowing another document context. Nested frames
            // also cannot navigate, even to the trusted chat origin.
            let isMainFrame = action.targetFrame?.isMainFrame == true
            decisionHandler(AgentChatNavigationPolicy.allowsDocumentNavigation(
                destination, isMainFrame: isMainFrame
            ) ? .allow : .cancel)
        }

        func webView(_ webView: WKWebView,
                     decidePolicyFor navigationResponse: WKNavigationResponse,
                     decisionHandler: @escaping (WKNavigationResponsePolicy) -> Void) {
            guard let destination = navigationResponse.response.url else {
                decisionHandler(.cancel)
                return
            }
            decisionHandler(AgentChatNavigationPolicy.allowsDocumentNavigation(
                destination, isMainFrame: navigationResponse.isForMainFrame
            ) ? .allow : .cancel)
        }
    }
}

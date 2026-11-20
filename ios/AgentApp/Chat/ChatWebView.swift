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
        configuration.userContentController.add(context.coordinator, name: "agentNative")
        let webView = WKWebView(frame: .zero, configuration: configuration)
        webView.navigationDelegate = context.coordinator
        webView.isInspectable = false
        webView.load(URLRequest(url: url, cachePolicy: .reloadIgnoringLocalCacheData))
        return webView
    }

    func updateUIView(_ webView: WKWebView, context: Context) {}

    static func dismantleUIView(_ webView: WKWebView, coordinator: Coordinator) {
        webView.stopLoading()
        webView.configuration.userContentController.removeScriptMessageHandler(forName: "agentNative")
        webView.navigationDelegate = nil
        webView.loadHTMLString("", baseURL: nil)
    }

    final class Coordinator: NSObject, WKNavigationDelegate, WKScriptMessageHandler {
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
            guard let url = action.request.url else {
                decisionHandler(.cancel)
                return
            }
            if url.scheme == "about" || (url.scheme == "http" &&
                url.host == AgentConstants.serverIPv4 && url.port == 8080) {
                decisionHandler(.allow)
            } else {
                decisionHandler(.cancel)
            }
        }

        func userContentController(_ userContentController: WKUserContentController,
                                   didReceive message: WKScriptMessage) {
            // No native actions or secrets exposed by default.
            guard message.frameInfo.isMainFrame,
                  message.frameInfo.securityOrigin.host == AgentConstants.serverIPv4 else { return }
        }
    }
}

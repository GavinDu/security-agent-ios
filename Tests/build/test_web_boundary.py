"""Static regression: only VPN-private document navigation; no inert native JS bridge."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]

class WebBoundaryTests(unittest.TestCase):
    def test_navigation_action_and_response_use_same_policy(self):
        source = (ROOT / "ios/AgentApp/Chat/ChatWebView.swift").read_text()
        self.assertIn("decidePolicyFor action: WKNavigationAction", source)
        self.assertIn("decidePolicyFor navigationResponse: WKNavigationResponse", source)
        self.assertEqual(source.count("AgentChatNavigationPolicy.allows(destination)"), 2)

    def test_inert_native_script_handler_is_not_exposed(self):
        source = (ROOT / "ios/AgentApp/Chat/ChatWebView.swift").read_text()
        self.assertNotIn("WKScriptMessageHandler", source)
        # WebKit content-blocking rule lists must be installed, but they
        # are NOT script message handlers and cannot invoke native callbacks.
        # Preserve the zero-JS-bridge invariant without forbidding the
        # new fail-closed resource allowlist.
        self.assertEqual(source.count("userContentController.add("), 1)
        self.assertIn("webView.configuration.userContentController.add(list)", source)
        self.assertNotIn("WKScriptMessageHandler", source)
        self.assertNotIn("agentNative", source)

    def test_private_origin_constraints_are_explicit(self):
        source = (ROOT / "ios/AgentApp/Chat/AgentChatNavigationPolicy.swift").read_text()
        for guard in ("components.scheme?.lowercased()",
                      "components.host == AgentConstants.serverIPv4",
                      "components.port == 8080",
                      "components.user == nil", "components.password == nil"):
            with self.subTest(guard=guard):
                self.assertIn(guard, source)

if __name__ == "__main__":
    unittest.main()

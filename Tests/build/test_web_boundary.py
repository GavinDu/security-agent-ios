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
        self.assertNotIn("userContentController.add(", source)
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

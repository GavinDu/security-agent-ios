"""Refuse third-party WebKit subresource requests before private page load."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
POLICY = (ROOT / "ios/AgentApp/Chat/AgentChatResourcePolicy.swift").read_text()
VIEW = (ROOT / "ios/AgentApp/Chat/ChatWebView.swift").read_text()
WORKFLOW = (ROOT / ".github/workflows/validate.yml").read_text()
SMOKE = (ROOT / "Tests/build/chat_resource_policy_smoke.swift").read_text()


class ChatResourceBoundaryTests(unittest.TestCase):
    def test_load_delayed_until_content_rules_installed(self):
        self.assertIn("AgentChatResourcePolicy.encodedRules()", VIEW)
        self.assertIn("compileContentRuleList(", VIEW)
        self.assertIn("webView.configuration.userContentController.add(list)", VIEW)
        self.assertLess(VIEW.index("compileContentRuleList("),
                        VIEW.index("webView.configuration.userContentController.add(list)"))
        self.assertLess(VIEW.index("webView.configuration.userContentController.add(list)"),
                        VIEW.index("webView.load(URLRequest("))
        self.assertIn("guard let list else", VIEW)
        self.assertIn("onLoadState(true)", VIEW)
        self.assertIn("coordinator.isActive = false", VIEW)

    def test_default_block_and_exact_private_exceptions(self):
        self.assertIn("^https?://", POLICY)
        self.assertIn('"ignore-previous-rules"', POLICY)
        self.assertIn("AgentConstants.serverIPv4", POLICY)
        self.assertIn(":8080/", POLICY)
        self.assertIn("https://cdn.example.com/script.js", SMOKE)
        self.assertIn("http://10.8.0.1.evil.example:8080/chat", SMOKE)
        self.assertIn("ws://10.8.0.1:8080/chat/stream", SMOKE)

    def test_compiled_production_policy_required_in_linux_workflow(self):
        self.assertIn("AgentChatResourcePolicy.swift", WORKFLOW)
        self.assertIn("chat_resource_policy_smoke.swift", WORKFLOW)


if __name__ == "__main__":
    unittest.main()

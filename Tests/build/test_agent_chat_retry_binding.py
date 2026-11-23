"""Native ContentView must actually reload and gate stale private WebKit callbacks."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
VIEW = (ROOT / "ios/AgentApp/ContentView.swift").read_text()
WEBKIT = (ROOT / "ios/AgentApp/Chat/ChatWebView.swift").read_text()
WORKFLOW = (ROOT / ".github/workflows/validate.yml").read_text()
TESTS = (ROOT / "Tests/iOS/AgentChatRetryStateTests.swift").read_text()


class AgentChatRetryBindingTests(unittest.TestCase):
    def test_only_connected_vpn_can_render_retried_webkit(self):
        self.assertIn("if tunnel.status == .connected {", VIEW)
        self.assertIn("let generation = chatRetry.generation", VIEW)
        self.assertIn("ChatWebView(url: AgentConstants.agentURL)", VIEW)
        self.assertIn(".id(generation)", VIEW)
        self.assertIn("chatRetry.reportLoadResult(", VIEW)
        self.assertIn("unreachable: failed, generation: generation", VIEW)
        self.assertIn("Button(\"Retry agent chat\")", VIEW)
        self.assertIn("chatRetry.retry()", VIEW)
        self.assertIn(".onChange(of: tunnel.status)", VIEW)
        self.assertIn("chatRetry.resetForVPNStatusChange()", VIEW)
        self.assertNotIn("serverUnavailable = failed", VIEW)

    def test_keeps_chat_isolated_and_native_tests_mandatory(self):
        self.assertIn("configuration.websiteDataStore = .nonPersistent()", WEBKIT)
        self.assertIn("webView.configuration.userContentController.add(list)", WEBKIT)
        self.assertIn("AgentChatNavigationPolicy.allowsDocumentNavigation", WEBKIT)
        self.assertNotIn("WKScriptMessageHandler", WEBKIT)
        self.assertIn("func testRetryRestartsChatAndIgnoresOldGenerationEvents()", TESTS)
        self.assertIn("func testVPNTransitionInvalidatesPreviousPageAndOverlay()", TESTS)
        self.assertIn("Shared/AgentChatRetryState.swift", WORKFLOW)
        self.assertIn("Tests/build/chat_retry_state_smoke.swift", WORKFLOW)
        self.assertIn("Tuist + iOS device and simulator XCTest", WORKFLOW)
        self.assertIn("python3 -m unittest discover -s Tests/build", WORKFLOW)


if __name__ == "__main__":
    unittest.main()

"""Private WebKit chat allows only top-level, exact trusted-origin documents."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
POLICY = (ROOT / "ios/AgentApp/Chat/AgentChatNavigationPolicy.swift").read_text()
WEBVIEW = (ROOT / "ios/AgentApp/Chat/ChatWebView.swift").read_text()
SMOKE = (ROOT / "Tests/build/chat_navigation_smoke.swift").read_text()
WORKFLOW = (ROOT / ".github/workflows/validate.yml").read_text()
XCTEST = (ROOT / "Tests/iOS/AgentChatNavigationPolicyTests.swift").read_text()


class ChatFrameNavigationSecurityTests(unittest.TestCase):
    def test_production_policy_rejects_nested_frames(self):
        f = POLICY.split("static func allowsDocumentNavigation(", 1)[1].split(
            "static func allows(", 1
        )[0]
        self.assertIn("guard isMainFrame else { return false }", f)
        self.assertIn("return allows(url)", f)
        self.assertIn('components.scheme?.lowercased() == "http"', POLICY)
        self.assertIn("components.host == AgentConstants.serverIPv4", POLICY)
        self.assertIn("components.port == 8080", POLICY)
        self.assertIn("components.user == nil, components.password == nil", POLICY)

    def test_both_navigation_delegates_reject_non_main_frame(self):
        action = WEBVIEW.split("decidePolicyFor action: WKNavigationAction", 1)[1].split(
            "decidePolicyFor navigationResponse: WKNavigationResponse", 1
        )[0]
        response = WEBVIEW.split(
            "decidePolicyFor navigationResponse: WKNavigationResponse", 1
        )[1]
        self.assertIn("action.targetFrame?.isMainFrame == true", action)
        self.assertIn("AgentChatNavigationPolicy.allowsDocumentNavigation(", action)
        self.assertIn("navigationResponse.isForMainFrame", response)
        self.assertIn("AgentChatNavigationPolicy.allowsDocumentNavigation(", response)
        self.assertIn("guard isActive, let destination = action.request.url", action)
        self.assertIn("guard isActive, let destination = navigationResponse.response.url", response)
        self.assertNotIn("decisionHandler(AgentChatNavigationPolicy.allows(destination)", WEBVIEW)

    def test_actual_compiled_swift_and_native_xctest_have_cases(self):
        self.assertIn("Tests/build/chat_navigation_smoke.swift", WORKFLOW)
        self.assertIn("ios/AgentApp/Chat/AgentChatNavigationPolicy.swift", WORKFLOW)
        self.assertIn("chat, isMainFrame: false", SMOKE)
        self.assertIn("chat, isMainFrame: true", SMOKE)
        self.assertIn("external, isMainFrame: true", SMOKE)
        self.assertIn("func testMainFrameOnlyNavigation()", XCTEST)


if __name__ == "__main__":
    unittest.main()

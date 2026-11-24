"""Only canonical private chat routes may become WKWebView top-level documents."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
POLICY = (ROOT / "ios/AgentApp/Chat/AgentChatNavigationPolicy.swift").read_text()
WEBVIEW = (ROOT / "ios/AgentApp/Chat/ChatWebView.swift").read_text()
SMOKE = (ROOT / "Tests/build/chat_navigation_smoke.swift").read_text()
NATIVE = (ROOT / "Tests/iOS/AgentChatNavigationPolicyTests.swift").read_text()
WORKFLOW = (ROOT / ".github/workflows/validate.yml").read_text()


class PrivateChatDocumentPathBoundaryTests(unittest.TestCase):
    def test_only_document_policy_adds_path_gate_and_origin_policy_is_preserved(self):
        entry = POLICY.split("static func allowsDocumentNavigation(", 1)[1].split(
            "private static func allowsChatDocumentPath(", 1
        )[0]
        self.assertIn("guard isMainFrame, allows(url)", entry)
        self.assertIn("URLComponents(url: url, resolvingAgainstBaseURL: false)", entry)
        self.assertIn("allowsChatDocumentPath(components.percentEncodedPath)", entry)
        origin = POLICY.split("static func allows(_ url: URL) -> Bool {", 1)[1]
        self.assertIn('components.scheme?.lowercased() == "http"', origin)
        self.assertIn("components.host == AgentConstants.serverIPv4", origin)
        self.assertIn("components.port == 8080", origin)
        self.assertIn("components.user == nil, components.password == nil", origin)
        self.assertNotIn("allowsChatDocumentPath(", origin)

    def test_path_validation_has_unambiguous_canonical_components(self):
        path = POLICY.split("private static func allowsChatDocumentPath(", 1)[1].split(
            "static func allows(_ url: URL)", 1
        )[0]
        self.assertIn('rawPath == "/chat"', path)
        self.assertIn('rawPath == "/chat/"', path)
        self.assertIn('rawPath.hasPrefix("/chat/")', path)
        self.assertIn("rawPath.utf8.count <= 1024", path)
        self.assertIn("segments.count <= 32", path)
        self.assertIn("segment.utf8.allSatisfy", path)
        for statement in ("byte == 45", "byte == 95", "index == segments.count - 1"):
            self.assertIn(statement, path)
        self.assertNotIn("removingPercentEncoding", path)

    def test_both_navigation_action_and_response_stay_path_scoped(self):
        self.assertIn("decidePolicyFor action: WKNavigationAction", WEBVIEW)
        self.assertIn("decidePolicyFor navigationResponse: WKNavigationResponse", WEBVIEW)
        self.assertEqual(
            WEBVIEW.count("AgentChatNavigationPolicy.allowsDocumentNavigation("), 2
        )
        self.assertIn("destination, isMainFrame: isMainFrame", WEBVIEW)
        self.assertIn("destination, isMainFrame: navigationResponse.isForMainFrame", WEBVIEW)
        self.assertIn("static func dismantleUIView(", WEBVIEW)

    def test_production_swift_linux_and_native_xctest_adversaries(self):
        self.assertIn("ios/AgentApp/Chat/AgentChatNavigationPolicy.swift", WORKFLOW)
        self.assertIn("Tests/build/chat_navigation_smoke.swift", WORKFLOW)
        self.assertIn("python3 -m unittest discover -s Tests/build", WORKFLOW)
        self.assertIn("Tuist + iOS device and simulator XCTest", WORKFLOW)
        for address in ("/admin", "/static/app.js", "/chat-admin", "/chat%2fadmin",
                        "/chat/%2e%2e/admin", "/chat//admin"):
            self.assertIn(address, SMOKE)
        self.assertIn("testOnlyCanonicalChatPathsBecomeTopLevelDocuments", NATIVE)
        self.assertIn("AgentChatNavigationPolicy.allows(", NATIVE)


if __name__ == "__main__":
    unittest.main()

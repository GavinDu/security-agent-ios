"""Regressions for the actual VPN-gated chat WKWebView storage boundary."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
CHAT = (ROOT / "ios/AgentApp/Chat/ChatWebView.swift").read_text()
NATIVE = (ROOT / "Tests/iOS/ChatWebViewLifecycleTests.swift").read_text()
WORKFLOW = (ROOT / ".github/workflows/validate.yml").read_text()
PROJECT = (ROOT / "Project.swift").read_text()


class PrivateChatWebKitStoreTests(unittest.TestCase):
    def test_configuration_factory_uses_ephemeral_site_storage(self):
        factory = CHAT.split("static func makePrivateConfiguration()", 1)[1].split(
            "func makeUIView(context: Context)", 1
        )[0]
        self.assertIn("let configuration = WKWebViewConfiguration()", factory)
        self.assertIn("configuration.websiteDataStore = .nonPersistent()", factory)
        self.assertIn("configuration.defaultWebpagePreferences.allowsContentJavaScript = true", factory)
        self.assertNotIn(".default()", factory)
        create = CHAT.split("func makeUIView(context: Context)", 1)[1].split(
            "func updateUIView", 1
        )[0]
        self.assertIn("let configuration = Self.makePrivateConfiguration()", create)
        self.assertLess(
            create.index("let configuration = Self.makePrivateConfiguration()"),
            create.index("WKWebView(frame: .zero, configuration: configuration)")
        )
        # Default data store is never rebound after the private factory call.
        self.assertNotIn("websiteDataStore =", create)
        self.assertIn("webView.configuration.userContentController.add(list)", create)
        self.assertIn("webView.isInspectable = false", create)

    def test_native_xctest_and_existing_security_suite_remain_required(self):
        self.assertIn("testPrivateChatConfigDisablesPersistentWebsiteData", NATIVE)
        self.assertIn("ChatWebView.makePrivateConfiguration()", NATIVE)
        self.assertIn("XCTAssertFalse(configuration.websiteDataStore.isPersistent)", NATIVE)
        self.assertIn("Tests/iOS/**/*.swift", PROJECT)
        self.assertIn("Tuist + iOS device and simulator XCTest", WORKFLOW)
        self.assertIn("python3 -m unittest discover -s Tests/build", WORKFLOW)
        self.assertIn("Tests/build/chat_resource_policy_smoke.swift", WORKFLOW)
        self.assertIn("AgentChatNavigationPolicy.allowsDocumentNavigation(", CHAT)
        self.assertNotIn("WKScriptMessageHandler", CHAT)


if __name__ == "__main__":
    unittest.main()

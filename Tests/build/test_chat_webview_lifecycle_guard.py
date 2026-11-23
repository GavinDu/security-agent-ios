"""Regression guard for stale WKWebView callbacks after VPN view teardown."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
SWIFT = (ROOT / "ios/AgentApp/Chat/ChatWebView.swift").read_text()


class ChatWebViewLifecycleBoundaryTests(unittest.TestCase):
    def test_dismantle_invalidates_coordinator_before_webkit_callbacks(self):
        teardown = SWIFT.split("static func dismantleUIView(", 1)[1].split(
            "final class Coordinator", 1
        )[0]
        self.assertLess(
            teardown.index("coordinator.isActive = false"),
            teardown.index("webView.stopLoading()"),
        )
        self.assertLess(
            teardown.index("coordinator.isActive = false"),
            teardown.index("webView.loadHTMLString("),
        )

    def test_all_navigation_results_pass_through_inactive_guard(self):
        coordinator = SWIFT.split("final class Coordinator", 1)[1]
        report = coordinator.split("func reportLoadResult(", 1)[1].split(
            "func webView(", 1
        )[0]
        self.assertIn("guard isActive else { return }", report)
        self.assertLess(
            report.index("guard isActive else { return }"),
            report.index("onLoadState(unreachable)"),
        )
        self.assertIn("didFinish navigation: WKNavigation!", coordinator)
        self.assertIn("didFailProvisionalNavigation navigation:", coordinator)
        self.assertIn("didFail navigation: WKNavigation!", coordinator)
        self.assertEqual(coordinator.count("reportLoadResult(false)"), 1)
        self.assertEqual(coordinator.count("reportLoadResult(true)"), 2)
        self.assertNotIn("onLoadState(false)", coordinator)
        self.assertNotIn("onLoadState(true)", coordinator)

    def test_both_navigation_decisions_cancel_when_inactive(self):
        coordinator = SWIFT.split("final class Coordinator", 1)[1]
        action = coordinator.split(
            "decidePolicyFor action: WKNavigationAction", 1
        )[1].split("decidePolicyFor navigationResponse:", 1)[0]
        response = coordinator.split(
            "decidePolicyFor navigationResponse: WKNavigationResponse", 1
        )[1]
        self.assertIn(
            "guard isActive, let destination = action.request.url else", action
        )
        self.assertIn(
            "guard isActive, let destination = navigationResponse.response.url else",
            response,
        )
        self.assertIn("decisionHandler(.cancel)", action)
        self.assertIn("decisionHandler(.cancel)", response)
        self.assertIn(
            "AgentChatNavigationPolicy.allowsDocumentNavigation(", action
        )
        self.assertIn(
            "AgentChatNavigationPolicy.allowsDocumentNavigation(", response
        )

    def test_native_xctest_is_in_mandatory_ci(self):
        native = (ROOT / "Tests/iOS/ChatWebViewLifecycleTests.swift").read_text()
        workflow = (ROOT / ".github/workflows/validate.yml").read_text()
        self.assertIn("testTornDownCoordinatorDiscardsLateLoadResults", native)
        self.assertIn("testInactiveCoordinatorNeverPublishesAnyResult", native)
        self.assertIn("python3 -m unittest discover -s Tests/build", workflow)
        self.assertIn("Run iOS Simulator XCTest", workflow)
        self.assertIn("Tuist + macOS companion build", workflow)


if __name__ == "__main__":
    unittest.main()

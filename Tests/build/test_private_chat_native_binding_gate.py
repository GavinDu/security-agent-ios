"""Private WebKit cannot be constructed on VPN .connected status alone."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
APP = (ROOT / "ios/AgentApp/VPN/TunnelManager.swift").read_text()
VIEW = (ROOT / "ios/AgentApp/ContentView.swift").read_text()
POLICY = (ROOT / "Shared/VPNPrivateChatAccessPolicy.swift").read_text()
WEBKIT = (ROOT / "ios/AgentApp/Chat/ChatWebView.swift").read_text()
WORKFLOW = (ROOT / ".github/workflows/validate.yml").read_text()
NATIVE = (ROOT / "Tests/iOS/VPNPrivateChatAccessTests.swift").read_text()


class VPNPrivateChatNativeBindingTests(unittest.TestCase):
    def test_tunnel_manager_requires_trusted_split_native_binding(self):
        segment = APP.split("var canShowPrivateChat: Bool {", 1)[1].split(
            "var statusDescription: String {", 1
        )[0]
        for required in (
            "profile.routeMode == .split",
            "(try? profile.validated()) != nil",
            "native.providerBundleIdentifier == AgentConstants.tunnelBundleID",
            "native.serverAddress == profile.endpoint",
            "NativeProfileBindingPolicy.allowsStart(",
            "metadata: native.providerConfiguration",
            "profileDigest: try? profile.publicProfileDigest()",
            "VPNPrivateChatAccessPolicy.permitsAccess(",
            "observedConnected: status == .connected",
            "nativeConnected: manager?.connection.status == .connected",
            "trustedNativeInventory: nativeInventoryTrust.permitsMutation",
            "verifiedSplitProfile: isValidSplitProfile",
            "nativeProfileBound: matchesNative",
            "noPreferenceWriteInFlight: !profileSave.isBusy && !legacyOnDemandDisableInFlight",
        ):
            with self.subTest(required=required):
                self.assertIn(required, segment)
        self.assertNotIn("SharedKeychain", segment)
        self.assertNotIn("startVPNTunnel()", segment)

    def test_only_verified_state_can_construct_chat_and_revoke_generation(self):
        self.assertIn("if tunnel.canShowPrivateChat {", VIEW)
        view_block = VIEW.split("if tunnel.canShowPrivateChat {", 1)[1].split(
            "} else if tunnel.status == .connected {", 1
        )[0]
        self.assertIn("ChatWebView(url: AgentConstants.agentURL)", view_block)
        self.assertIn(".id(generation)", view_block)
        self.assertIn("Verify VPN configuration", VIEW)
        self.assertIn(".onChange(of: tunnel.canShowPrivateChat)", VIEW)
        self.assertIn("chatRetry.resetForVPNStatusChange()", VIEW)
        self.assertNotIn("if tunnel.status == .connected {", VIEW)

    def test_fail_closed_policy_and_native_ci_keep_earlier_webkit_isolation(self):
        for guard in (
            "observedConnected && nativeConnected && trustedNativeInventory",
            "verifiedSplitProfile && nativeProfileBound && noPreferenceWriteInFlight",
        ):
            self.assertIn(guard, POLICY)
        self.assertIn("configuration.websiteDataStore = .nonPersistent()", WEBKIT)
        self.assertIn("webView.configuration.userContentController.add(list)", WEBKIT)
        self.assertIn("AgentChatNavigationPolicy.allowsDocumentNavigation(", WEBKIT)
        self.assertNotIn("WKScriptMessageHandler", WEBKIT)
        self.assertIn("testConnectedStatusAloneCannotAuthorizePrivateWebKit", NATIVE)
        self.assertIn("testExistingNativeProfileDigestIsStillSingleSourceOfTruth", NATIVE)
        self.assertIn("Shared/VPNPrivateChatAccessPolicy.swift", WORKFLOW)
        self.assertIn("Tests/build/vpn_private_chat_access_smoke.swift", WORKFLOW)
        self.assertIn("Tuist + iOS device and simulator XCTest", WORKFLOW)
        self.assertIn("Tuist + macOS companion build", WORKFLOW)
        self.assertIn("python3 -m unittest discover -s Tests/build", WORKFLOW)


if __name__ == "__main__":
    unittest.main()

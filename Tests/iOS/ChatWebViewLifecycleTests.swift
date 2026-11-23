import XCTest
@testable import AgentApp

/// Exercises the real ChatWebView coordinator without loading any network URL.
final class ChatWebViewLifecycleTests: XCTestCase {
    func testPrivateChatConfigDisablesPersistentWebsiteData() {
        // Exercise the actual WKWebView factory used before the first
        // VPN-private navigation; no network request or signed tunnel needed.
        let configuration = ChatWebView.makePrivateConfiguration()
        XCTAssertFalse(configuration.websiteDataStore.isPersistent)
        XCTAssertTrue(configuration.defaultWebpagePreferences.allowsContentJavaScript)
        XCTAssertTrue(configuration.userContentController.userScripts.isEmpty)
    }

    func testActiveCoordinatorReportsSuccessAndFailures() {
        var received: [Bool] = []
        let coordinator = ChatWebView.Coordinator { received.append($0) }

        coordinator.reportLoadResult(false)
        coordinator.reportLoadResult(true)
        coordinator.reportLoadResult(false)
        XCTAssertEqual(received, [false, true, false])
    }

    func testTornDownCoordinatorDiscardsLateLoadResults() {
        var received: [Bool] = []
        let coordinator = ChatWebView.Coordinator { received.append($0) }

        coordinator.reportLoadResult(false)
        coordinator.isActive = false
        // Simulates WebKit delegate callbacks arriving after dismantleUIView.
        coordinator.reportLoadResult(true)
        coordinator.reportLoadResult(false)
        XCTAssertEqual(received, [false])
    }

    func testInactiveCoordinatorNeverPublishesAnyResult() {
        var received: [Bool] = []
        let coordinator = ChatWebView.Coordinator { received.append($0) }
        coordinator.isActive = false
        coordinator.reportLoadResult(false)
        coordinator.reportLoadResult(true)
        XCTAssertTrue(received.isEmpty)
    }
}

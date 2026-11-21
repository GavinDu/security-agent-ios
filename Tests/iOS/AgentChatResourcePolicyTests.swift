import Foundation
import WebKit
import XCTest
@testable import AgentApp

final class AgentChatResourcePolicyTests: XCTestCase {
    func testRulesHaveBlockingDefaultAndTwoExactExceptions() throws {
        let text = try AgentChatResourcePolicy.encodedRules()
        let decoded = try XCTUnwrap(
            JSONSerialization.jsonObject(with: Data(text.utf8)) as?
                [[String: [String: String]]]
        )
        XCTAssertEqual(decoded.count, 4)
        XCTAssertEqual(decoded.compactMap { $0["action"]?["type"] },
                       ["block", "block", "ignore-previous-rules", "ignore-previous-rules"])
        XCTAssertEqual(decoded[0]["trigger"]?["url-filter"],
                       "^https?://")
        XCTAssertEqual(decoded[1]["trigger"]?["url-filter"],
                       "^wss?://")
        XCTAssertEqual(decoded[2]["trigger"]?["url-filter"],
                       "^http://10\\.8\\.0\\.1:8080/")
        XCTAssertEqual(decoded[3]["trigger"]?["url-filter"],
                       "^ws://10\\.8\\.0\\.1:8080/")
    }

    func testWebKitAcceptsRulesBeforeFirstNavigation() throws {
        let ruleSource = try AgentChatResourcePolicy.encodedRules()
        let completion = expectation(description: "WebKit chat resource rule compilation")
        WKContentRuleListStore.default().compileContentRuleList(
            forIdentifier: AgentChatResourcePolicy.identifier + ".tests",
            encodedContentRuleList: ruleSource
        ) { list, error in
            XCTAssertNil(error)
            XCTAssertNotNil(list)
            completion.fulfill()
        }
        wait(for: [completion], timeout: 20)
    }
}

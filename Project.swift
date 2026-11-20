import Foundation
import ProjectDescription

// Replace this with your Apple Developer Team ID before signing.
let teamID = ProcessInfo.processInfo.environment["AGENT_APP_TEAM_ID"] ?? ""

let common: SettingsDictionary = [
    "SWIFT_VERSION": "5.9",
    "IPHONEOS_DEPLOYMENT_TARGET": "17.6",
    "MACOSX_DEPLOYMENT_TARGET": "14.0",
    "MARKETING_VERSION": "0.1.0",
    "CURRENT_PROJECT_VERSION": "1",
    "CODE_SIGN_STYLE": "Automatic"
]
let signing = common.merging(["DEVELOPMENT_TEAM": .string(teamID)]) { _, new in new }

let project = Project(
    name: "SecurityAgent",
    targets: [
        .target(
            name: "AgentApp",
            destinations: .iOS,
            product: .app,
            bundleId: "com.gavindu.securityagent.ios",
            deploymentTargets: .iOS("17.6"),
            infoPlist: .extendingDefault(with: [
                "CFBundleDisplayName": "Security Agent",
                "AgentKeychainAccessGroup": "$(AppIdentifierPrefix)com.gavindu.securityagent.shared",
                "NSCameraUsageDescription": "Scan a pairing QR code from your Mac Mini.",
                "NSMicrophoneUsageDescription": "Record a voice prompt when you choose voice input.",
                "NSSpeechRecognitionUsageDescription": "Transcribe speech into a chat prompt.",
                "NSAppTransportSecurity": [
                    "NSAllowsArbitraryLoadsInWebContent": true
                ]
            ]),
            sources: ["ios/AgentApp/**/*.swift", "Shared/**/*.swift"],
            entitlements: "ios/Entitlements/AgentApp.entitlements",
            dependencies: [.target(name: "PacketTunnel")],
            settings: .settings(base: signing)
        ),
        .target(
            name: "PacketTunnel",
            destinations: .iOS,
            product: .appExtension,
            bundleId: "com.gavindu.securityagent.ios.PacketTunnel",
            deploymentTargets: .iOS("17.6"),
            infoPlist: .extendingDefault(with: [
                "CFBundleDisplayName": "Agent Packet Tunnel",
                "AgentKeychainAccessGroup": "$(AppIdentifierPrefix)com.gavindu.securityagent.shared",
                "NSExtension": [
                    "NSExtensionPointIdentifier": "com.apple.networkextension.packet-tunnel",
                    "NSExtensionPrincipalClass": "$(PRODUCT_MODULE_NAME).PacketTunnelProvider"
                ]
            ]),
            sources: ["ios/PacketTunnel/**/*.swift", "Shared/**/*.swift"],
            entitlements: "ios/Entitlements/PacketTunnel.entitlements",
            dependencies: [.external(name: "WireGuardKit")],
            settings: .settings(base: signing)
        ),
        .target(
            name: "AgentMac",
            destinations: .macOS,
            product: .app,
            bundleId: "com.gavindu.securityagent.macos",
            deploymentTargets: .macOS("14.0"),
            infoPlist: .extendingDefault(with: [
                "CFBundleDisplayName": "Security Agent Mac"
            ]),
            sources: ["macos/AgentMac/**/*.swift", "Shared/**/*.swift"],
            settings: .settings(base: signing)
        ),
        .target(
            name: "AgentAppTests",
            destinations: .iOS,
            product: .unitTests,
            bundleId: "com.gavindu.securityagent.ios.tests",
            deploymentTargets: .iOS("17.6"),
            sources: ["Tests/iOS/**/*.swift"],
            dependencies: [.target(name: "AgentApp")],
            settings: .settings(base: signing)
        )
    ],
    schemes: [
        .scheme(
            name: "AgentApp",
            shared: true,
            buildAction: .buildAction(targets: [.target("AgentApp")]),
            testAction: .targets([.testableTarget(target: .target("AgentAppTests"))])
        ),
        .scheme(name: "AgentMac", shared: true, buildAction: .buildAction(targets: [.target("AgentMac")]))
    ]
)

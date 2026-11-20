// swift-tools-version: 5.9
import PackageDescription

#if TUIST
import ProjectDescription
let packageSettings = PackageSettings(productTypes: ["WireGuardKit": .framework])
#endif

let package = Package(
    name: "SecurityAgentDependencies",
    dependencies: [
        // WireGuardKit requires a separately built WireGuardKitGo bridge.
        // See docs/WIREGUARD_BUILD.md before building PacketTunnel on device.
        .package(url: "https://github.com/WireGuard/wireguard-apple", branch: "master")
    ]
)

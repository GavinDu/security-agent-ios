// swift-tools-version: 5.9
import PackageDescription

#if TUIST
import ProjectDescription
let packageSettings = PackageSettings(productTypes: ["WireGuardKit": .framework])
#endif

let package = Package(
    name: "SecurityAgentDependencies",
    dependencies: [
        // Exact WireGuard source revision; no floating master/branch.
        // Matches scripts/build-wireguard-go.sh and docs/WIREGUARD_BUILD.md.
        .package(
            url: "https://github.com/WireGuard/wireguard-apple",
            revision: "2fec12a6e1f6e3460b6ee483aa00ad29cddadab1"
        )
    ]
)

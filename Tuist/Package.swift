// swift-tools-version: 5.9
import PackageDescription

#if TUIST
import ProjectDescription
// WireGuardKitGo is linked as a static Go archive by PacketTunnel.
// A dynamic WireGuardKit framework may attempt to resolve -lwg-go in its
// own framework link step, before PacketTunnel builds the archive.
let packageSettings = PackageSettings(productTypes: ["WireGuardKit": .staticFramework])
#endif

let package = Package(
    name: "SecurityAgentDependencies",
    dependencies: [
        // Local pinned upstream checkout, prepared by scripts/bootstrap-wireguard.sh.
        // The upstream Package.swift header is repaired, not implementation code.
        .package(path: "../Vendor/wireguard-apple")
    ]
)

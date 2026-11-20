# WireGuardKit integration and Apple signing

**Not yet device-build-verified.** This project references the upstream
`WireGuardKit` Swift package in `Tuist/Package.swift` and links it to
`PacketTunnel`. The upstream authors state that SPM cannot automatically
build the `wireguard-go-bridge` library which WireGuardKit links against.

Follow the [official WireGuard Apple README](https://github.com/WireGuard/wireguard-apple/blob/master/README.md#wireguardkit-integration)
for your Xcode/Tuist version. In particular:

1. Install Go and Xcode command line tools on the Mac.
2. Run `tuist install` and `tuist generate`, open the project in Xcode.
3. Add an **External Build System** target named `WireGuardGoBridgeiOS`
   using build tool `/usr/bin/make` and directory:
   ```text
   ${BUILD_DIR%Build/*}SourcePackages/checkouts/wireguard-apple/Sources/WireGuardKitGo
   ```
   Set SDKROOT to `iphoneos` and make PacketTunnel depend on this target.
   Ensure WireGuardKit is linked to PacketTunnel. Tuist regeneration may
   remove changes made only in the generated project; a production step
   must encode this bridge target in maintained build configuration.
4. Sign both iOS targets using the same development team and provisioning
   profiles with Packet Tunnel Network Extension, shared Keychain group and
   App Group entitlements. Bundle IDs in Project.swift are examples;
   confirm these IDs are available in your Apple Developer account.
5. Test on an actual iPhone. A simulator-only build is insufficient for
   validating a VPN or background system extension.

`AgentKeychainAccessGroup` must expand to the fully-qualified shared
Keychain group such as `<TEAM_PREFIX>.com.gavindu.securityagent.shared`.
The iPhone app and extension must have the identical value.

## Initial build commands

```sh
export AGENT_APP_TEAM_ID=YOUR_TEAM_ID
tuist install
tuist generate
xcodebuild -list -project SecurityAgent.xcodeproj
# Device build after completing Go bridge target + signing configuration:
xcodebuild -project SecurityAgent.xcodeproj -scheme AgentApp \
  -configuration Debug -destination 'generic/platform=iOS' build
```

Do **not** interpret the source-syntax GitHub Action as proof of a complete
native build. A signed device build, WireGuard handshake, route and browser
tests are acceptance gates before calling the VPN functional.

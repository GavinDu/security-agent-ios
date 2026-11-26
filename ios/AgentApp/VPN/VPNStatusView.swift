import NetworkExtension
import SwiftUI

struct VPNStatusView: View {
    @ObservedObject var tunnel: TunnelManager

    var body: some View {
        Form {
            Section("Connection") {
                LabeledContent("Status", value: tunnel.statusDescription)
                LabeledContent("System auto-connect", value: tunnel.nativeAutoConnectDescription)
                if let profile = tunnel.profile {
                    LabeledContent("Server", value: profile.endpoint)
                    LabeledContent("Routing", value: profile.routeMode.title)
                } else {
                    Text("Scan a pairing QR from the Mac Mini to configure WireGuard.")
                        .foregroundStyle(.secondary)
                }
                Button("Retry loading VPN preferences") { tunnel.reload() }
                    .font(.footnote)
                    .accessibilityHint("Checks saved system VPN entries after a permission or load failure.")
                HStack {
                    Button("Connect") { tunnel.connect() }
                        .disabled(tunnel.profile == nil || tunnel.profile?.routeMode == .full ||
                                  tunnel.status == .connected || tunnel.status == .connecting || tunnel.isChangingRoute)
                    Spacer()
                    Button("Disconnect") { tunnel.disconnect() }
                        .disabled(tunnel.status == .disconnected || tunnel.status == .invalid)
                }
            }

            Section("Recent VPN events") {
                let events = SharedDiagnostics.events()
                if events.isEmpty {
                    Text("No packet tunnel events yet").foregroundStyle(.secondary)
                } else {
                    ForEach(Array(events.suffix(5).reversed())) { entry in
                        LabeledContent(entry.event.replacingOccurrences(of: "_", with: " "),
                                       value: entry.at.formatted(date: .abbreviated, time: .standard))
                    }
                }
                Text("The log stores only state transitions and timestamps. No keys or network payloads.")
                    .font(.footnote).foregroundStyle(.secondary)
                if !events.isEmpty {
                    // Sharing requires an explicit tap; never upload diagnostics
                    // or share the raw App Group file/unknown event strings.
                    ShareLink(item: VPNEventExport.redactedText(from: events)) {
                        Label("Share redacted VPN events", systemImage: "square.and.arrow.up")
                    }
                    .accessibilityHint("Share only approved VPN state changes and UTC timestamps.")
                }
            }

            if let profile = tunnel.profile {
                Section("Routing") {
                    Picker("Mode", selection: Binding(
                        get: { tunnel.profile?.routeMode ?? .split },
                        set: { tunnel.changeRoute(to: $0) }
                    )) {
                        ForEach(RouteMode.allCases) { mode in
                            Text(mode.title).tag(mode)
                        }
                    }
                    .pickerStyle(.segmented)
                    .disabled(tunnel.isChangingRoute)
                    if tunnel.isChangingRoute {
                        ProgressView("Waiting for VPN to disconnect…")
                    }
                    Text("Full tunnel is disabled pending physical-device verification of encrypted UDP routing and IPv4/IPv6 leak safety.")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                    Text(profile.routeMode == .split
                         ? "Only 10.8.0.0/24 is sent through the VPN. Regular browsing uses your current network."
                         : "This saved full-tunnel profile is blocked for safety. Disconnect and switch to split tunnel before connecting.")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                    Text("For route changes: turn off Connect on demand, then choose the new mode. The VPN will disconnect before saving. Connect manually afterward.")
                        .font(.footnote)
                }
                Section("Reliability") {
                    Toggle("Connect on demand", isOn: Binding(
                        get: { tunnel.profile?.onDemand ?? false },
                        set: { tunnel.setOnDemand($0) }
                    ))
                    .disabled(profile.routeMode == .full)
                    .disabled(tunnel.isChangingRoute)
                    if profile.routeMode == .full {
                        Text("The saved flag may differ from System auto-connect above. Legacy recovery disables native auto-connect without re-enabling full tunnel.")
                            .font(.footnote).foregroundStyle(.secondary)
                    }
                    Text("Enable only after testing a manual connection on a physical iPhone.")
                        .font(.footnote).foregroundStyle(.secondary)
                }
            }
        }
        .navigationTitle("VPN settings")
        .alert("VPN error", isPresented: Binding(
            get: { tunnel.errorMessage != nil },
            set: { if !$0 { tunnel.errorMessage = nil } }
        )) {
            Button("OK") { tunnel.errorMessage = nil }
        } message: {
            Text(tunnel.errorMessage ?? "")
        }
    }
}

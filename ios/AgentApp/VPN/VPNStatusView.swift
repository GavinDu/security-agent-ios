import NetworkExtension
import SwiftUI

struct VPNStatusView: View {
    @ObservedObject var tunnel: TunnelManager

    var body: some View {
        Form {
            Section("Connection") {
                LabeledContent("Status", value: tunnel.statusDescription)
                if let profile = tunnel.profile {
                    LabeledContent("Server", value: profile.endpoint)
                    LabeledContent("Routing", value: profile.routeMode.title)
                } else {
                    Text("Scan a pairing QR from the Mac Mini to configure WireGuard.")
                        .foregroundStyle(.secondary)
                }
                HStack {
                    Button("Connect") { tunnel.connect() }
                        .disabled(tunnel.profile == nil || tunnel.status == .connected ||
                                  tunnel.status == .connecting)
                    Spacer()
                    Button("Disconnect") { tunnel.disconnect() }
                        .disabled(tunnel.status == .disconnected || tunnel.status == .invalid)
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
                    Text(profile.routeMode == .split
                         ? "Only 10.8.0.0/24 is sent through the VPN. Regular browsing uses your current network."
                         : "All IPv4 and IPv6 routes use the VPN. Your Mac must provide internet forwarding and IPv6 connectivity.")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                    Text("After changing modes, wait for disconnect to finish, then tap Connect.")
                        .font(.footnote)
                }
                Section("Reliability") {
                    Toggle("Connect on demand", isOn: Binding(
                        get: { tunnel.profile?.onDemand ?? false },
                        set: { tunnel.setOnDemand($0) }
                    ))
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

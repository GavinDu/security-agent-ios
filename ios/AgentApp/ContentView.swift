import SwiftUI

struct ContentView: View {
    @ObservedObject var tunnel: TunnelManager
    @State private var serverUnavailable = false

    var body: some View {
        TabView {
            NavigationStack {
                Group {
                    if tunnel.status == .connected {
                        ZStack {
                            ChatWebView(url: AgentConstants.agentURL) { failed in
                                serverUnavailable = failed
                            }
                            .ignoresSafeArea(edges: .bottom)

                            if serverUnavailable {
                                ContentUnavailableView(
                                    "Mac Mini unavailable",
                                    systemImage: "wifi.exclamationmark",
                                    description: Text("VPN is connected, but the agent server at 10.8.0.1:8080 cannot be reached.")
                                )
                            }
                        }
                    } else {
                        ContentUnavailableView(
                            "Connect VPN",
                            systemImage: "lock.shield",
                            description: Text("Agent chat is available only while the WireGuard VPN is connected.")
                        )
                        .safeAreaInset(edge: .bottom) {
                            Button("Open VPN settings") { tunnel.showSettings = true }
                                .buttonStyle(.borderedProminent)
                                .padding()
                        }
                    }
                }
                .navigationTitle("Agent")
                .navigationBarTitleDisplayMode(.inline)
            }
            .tabItem { Label("Chat", systemImage: "message") }

            NavigationStack { PairingView(tunnel: tunnel) }
                .tabItem { Label("Pair", systemImage: "qrcode") }

            NavigationStack { VPNStatusView(tunnel: tunnel) }
                .tabItem { Label("VPN", systemImage: "network.badge.shield.half.filled") }
        }
        .sheet(isPresented: $tunnel.showSettings) {
            NavigationStack {
                VPNStatusView(tunnel: tunnel)
                    .toolbar { ToolbarItem(placement: .topBarTrailing) {
                        Button("Done") { tunnel.showSettings = false }
                    } }
            }
        }
    }
}

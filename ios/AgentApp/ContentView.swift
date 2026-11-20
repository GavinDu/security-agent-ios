import SwiftUI

struct ContentView: View {
    @ObservedObject var tunnel: TunnelManager

    var body: some View {
        TabView {
            NavigationStack {
                Group {
                    if tunnel.status == .connected {
                        ChatWebView(url: AgentConstants.agentURL)
                            .ignoresSafeArea(edges: .bottom)
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

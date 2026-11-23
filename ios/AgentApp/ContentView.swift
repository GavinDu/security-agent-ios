import SwiftUI

struct ContentView: View {
    @ObservedObject var tunnel: TunnelManager
    @State private var chatRetry = AgentChatRetryState()

    var body: some View {
        TabView {
            NavigationStack {
                Group {
                    if tunnel.canShowPrivateChat {
                        let generation = chatRetry.generation
                        ZStack {
                            ChatWebView(url: AgentConstants.agentURL) { failed in
                                // Ignore late results from an earlier page or
                                // from a session dismissed by a VPN transition.
                                chatRetry.reportLoadResult(
                                    unreachable: failed, generation: generation
                                )
                            }
                            .id(generation)
                            .ignoresSafeArea(edges: .bottom)

                            if chatRetry.isUnavailable {
                                VStack(spacing: 12) {
                                    ContentUnavailableView(
                                        "Mac Mini unavailable",
                                        systemImage: "wifi.exclamationmark",
                                        description: Text("VPN is connected, but the agent server at 10.8.0.1:8080 cannot be reached.")
                                    )
                                    Button("Retry agent chat") {
                                        chatRetry.retry()
                                    }
                                    .buttonStyle(.borderedProminent)
                                    .accessibilityHint("Reload the private agent page while keeping VPN connected.")
                                }
                            }
                        }
                    } else if tunnel.status == .connected {
                        ContentUnavailableView(
                            "Verify VPN configuration",
                            systemImage: "lock.trianglebadge.exclamationmark",
                            description: Text("The connected VPN does not match a verified split-tunnel Mac profile. Retry loading VPN preferences or re-pair before opening private chat.")
                        )
                        .safeAreaInset(edge: .bottom) {
                            Button("Open VPN settings") { tunnel.showSettings = true }
                                .buttonStyle(.borderedProminent)
                                .padding()
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
        .onChange(of: tunnel.status) { oldStatus, newStatus in
            guard oldStatus != newStatus else { return }
            // Reject late callbacks after any transport status transition.
            chatRetry.resetForVPNStatusChange()
        }
        .onChange(of: tunnel.canShowPrivateChat) { oldAccess, newAccess in
            guard oldAccess != newAccess else { return }
            // A changed native binding or inventory can revoke access while
            // the OS still reports Connected. Invalidate old WebKit results.
            chatRetry.resetForVPNStatusChange()
        }
    }
}

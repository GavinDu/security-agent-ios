import SwiftUI

@main
struct SecurityAgentApp: App {
    @StateObject private var tunnel = TunnelManager()

    var body: some Scene {
        WindowGroup {
            ContentView(tunnel: tunnel)
        }
    }
}

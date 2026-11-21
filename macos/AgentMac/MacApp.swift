import SwiftUI

@main
struct AgentMacApp: App {
    var body: some Scene {
        WindowGroup {
            MacDashboard()
                .frame(minWidth: 620, minHeight: 570)
        }
    }
}

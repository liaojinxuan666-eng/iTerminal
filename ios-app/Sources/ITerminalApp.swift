import SwiftUI

@main
struct ITerminalApp: App {
    @StateObject private var session = ITerminalSession()

    var body: some Scene {
        WindowGroup {
            TerminalView(session: session)
                .preferredColorScheme(.dark)
                .onAppear {
                    session.startBundledRuntime()
                }
        }
    }
}

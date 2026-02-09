import SwiftUI

@main
struct SecureChatApp: App {
    @StateObject private var appViewModel = AppViewModel()
    
    init() {
        LogManager.shared.setup()
    }

    var body: some Scene {
        WindowGroup {
            ContentView(viewModel: appViewModel)
                .preferredColorScheme(.dark)
                .onOpenURL { url in
                    appViewModel.handleDeepLink(url)
                }
        }
    }
}

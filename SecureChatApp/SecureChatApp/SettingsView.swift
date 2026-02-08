import SwiftUI

struct SettingsView: View {
    @EnvironmentObject var appViewModel: AppViewModel
    @EnvironmentObject var chatViewModel: ChatViewModel
    
    var body: some View {
        NavigationView {
            List {
                Section("Peer Identity") {
                    VStack(alignment: .leading, spacing: 8) {
                        Text("Peer ID")
                            .font(.caption)
                            .foregroundColor(.secondary)
                        Text(appViewModel.peerId.isEmpty ? "Connecting..." : appViewModel.peerId)
                            .font(.system(.caption, design: .monospaced))
                            .textSelection(.enabled)
                    }
                    .padding(.vertical, 4)
                }
                
                if let bundle = chatViewModel.prekeyBundleJson {
                    Section("PreKey Bundle (for CLI /session)") {
                        VStack(alignment: .leading, spacing: 8) {
                            Text(bundle)
                                .font(.system(.caption2, design: .monospaced))
                                .textSelection(.enabled)
                            
                            Button("Copy Bundle") {
                                UIPasteboard.general.string = bundle
                            }
                            .buttonStyle(.borderedProminent)
                        }
                        .padding(.vertical, 4)
                    }
                }
                
                Section("Network Status") {
                    HStack {
                        Text("Status")
                        Spacer()
                        Text(appViewModel.isRunning ? "Connected" : "Disconnected")
                            .foregroundColor(appViewModel.isRunning ? .green : .red)
                    }
                    
                    HStack {
                        Text("Discovered Peers")
                        Spacer()
                        Text("\(appViewModel.peers.count)")
                    }
                }
            }
            .navigationTitle("Settings")
        }
    }
}

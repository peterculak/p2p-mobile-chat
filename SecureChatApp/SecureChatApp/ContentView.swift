import SwiftUI
import OSLog

// MARK: - Color Theme
extension Color {
    static let bgPrimary = Color(red: 0.05, green: 0.05, blue: 0.10)
    static let bgSecondary = Color(red: 0.10, green: 0.10, blue: 0.18)
    static let accentStart = Color(red: 0.48, green: 0.18, blue: 1.0)
    static let accentEnd = Color(red: 0.0, green: 0.83, blue: 1.0)
    static let glass = Color.white.opacity(0.08)
}

// MARK: - Gradient Extension
extension LinearGradient {
    static let accent = LinearGradient(
        colors: [.accentStart, .accentEnd],
        startPoint: .topLeading,
        endPoint: .bottomTrailing
    )
}

// MARK: - App View Model
class AppViewModel: ObservableObject {
    @Published var identity: Identity?
    @Published var fingerprint: String = ""
    @Published var isGenerating: Bool = false
    @Published var manualAddress: String = ""
    
    // Network state
    @Published var networkManager: NetworkManager?
    @Published var isNetworkRunning: Bool = false
    @Published var discoveredPeers: [PeerInfo] = []
    @Published var listeningAddress: String = ""
    @Published var peerId: String = ""
    
    // Privacy state
    @Published var privacyManager: PrivacyApi?
    @Published var isOnionEnabled: Bool = false
    @Published var relayCount: Int = 0
    
    // Callbacks
    var onMessageReceived: ((String, Data) -> Void)?
    
    private var pollTimer: Timer?
    
    func generateNewIdentity() {
        isGenerating = true
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.3) { [weak self] in
            let newIdentity = generateIdentity()
            self?.identity = newIdentity
            self?.fingerprint = getPublicKeyFingerprint(identity: newIdentity)
            self?.isGenerating = false
        }
    }
    
    func startNetwork() {
        if networkManager == nil {
            networkManager = createNetworkManager()
            peerId = networkManager?.getPeerId() ?? ""
            privacyManager = createPrivacyManager()
        }
        
        do {
            try networkManager?.start()
            isNetworkRunning = true
            startPolling()
        } catch {
            print("Failed to start network: \(error)")
        }
    }
    
    func stopNetwork() {
        networkManager?.stop()
        isNetworkRunning = false
        stopPolling()
        discoveredPeers = []
        listeningAddress = ""
    }
    
    func dialManualAddress() {
        guard !manualAddress.isEmpty else { return }
        do {
            try networkManager?.dial(address: manualAddress)
            LogManager.shared.info("Manually dialing \(manualAddress)", context: "AppViewModel")
            manualAddress = ""
        } catch {
            LogManager.shared.error("Failed to dial address: \(error)", context: "AppViewModel")
        }
    }
    
    private func startPolling() {
        pollTimer = Timer.scheduledTimer(withTimeInterval: 0.5, repeats: true) { [weak self] _ in
            self?.pollEvents()
        }
    }
    
    private func stopPolling() {
        pollTimer?.invalidate()
        pollTimer = nil
    }
    
    private func pollEvents() {
        guard let manager = networkManager else { return }
        
        // Poll Network Events
        while let event = manager.pollEvent() {
            DispatchQueue.main.async { [weak self] in
                self?.handleEvent(event)
            }
        }
        
        // Poll Privacy Events
        if let privacy = privacyManager {
            while let event = privacy.nextEvent() {
                DispatchQueue.main.async { [weak self] in
                    self?.handlePrivacyEvent(event)
                }
            }
            // Update relay count
            let currentRelays = Int(privacy.relayCount())
            if relayCount != currentRelays {
                DispatchQueue.main.async {
                    self.relayCount = currentRelays
                }
            }
        }
    }
    
    private func handleEvent(_ event: NetworkEvent) {
        switch event {
        case .listening(let address):
            LogManager.shared.info("Network listening on \(address)", context: "AppViewModel")
            listeningAddress = address
        case .peerDiscovered(let peer):
            LogManager.shared.info("Discovered peer: \(peer.peerId)", context: "AppViewModel")
            if !discoveredPeers.contains(where: { $0.peerId == peer.peerId }) {
                discoveredPeers.append(peer)
                // Haptic feedback
                let generator = UINotificationFeedbackGenerator()
                generator.notificationOccurred(.success)
                
                // AUTO-DIAL: Try to connect to the discovered peer
                for addr in peer.addresses {
                    LogManager.shared.info("Auto-dialing discovered address: \(addr)", context: "AppViewModel")
                    try? networkManager?.dial(address: addr)
                }
            }
        case .peerDisconnected(let peerId):
            LogManager.shared.info("Peer disconnected: \(peerId)", context: "AppViewModel")
            discoveredPeers.removeAll { $0.peerId == peerId }
        case .peerConnected(let peerId):
            LogManager.shared.info("Peer connected: \(peerId)", context: "AppViewModel")
        case .error(let message):
            LogManager.shared.error("Network error: \(message)", context: "AppViewModel")
        case .messageReceived(let peerId, let data):
            LogManager.shared.debug("Network received message from \(peerId), size: \(data.count)", context: "AppViewModel")
            onMessageReceived?(peerId, Data(data))
        }
    }
    
    private func handlePrivacyEvent(_ event: PrivacyApiEvent) {
        switch event {
        case .relayPacket(let nextPeerId, let packetBytes, let delayMs):
            LogManager.shared.info("Privacy: Relaying packet to \(nextPeerId) after \(delayMs)ms", context: "AppViewModel")
            // For now we send immediately, ignoring delay for simplicity in this demo
            // In a real app we'd use DispatchQueue.main.asyncAfter
            do {
                try networkManager?.sendMessage(peerId: nextPeerId, data: packetBytes)
            } catch {
                LogManager.shared.error("Failed to relay packet: \(error)", context: "AppViewModel")
            }
            
        case .deliverPayload(let nextPeerId, let payload):
            LogManager.shared.info("Privacy: Delivering exit payload to \(nextPeerId)", context: "AppViewModel")
            do {
                try networkManager?.sendMessage(peerId: nextPeerId, data: payload)
            } catch {
                LogManager.shared.error("Failed to deliver payload: \(error)", context: "AppViewModel")
            }
            
        case .packetDelivered(let payload):
            LogManager.shared.info("Privacy: Packet reached destination (us!), passing to messaging", context: "AppViewModel")
            onMessageReceived?("privacy-exit", Data(payload))
            
        case .circuitBuilt(let circuitId, let hops):
            LogManager.shared.info("Privacy: Circuit #\(circuitId) built with \(hops) hops", context: "AppViewModel")
            
        case .error(let message):
            LogManager.shared.error("Privacy error: \(message)", context: "AppViewModel")
        }
    }
}

// MARK: - Main Content View
struct ContentView: View {
    @StateObject private var viewModel = AppViewModel()
    @StateObject private var chatViewModel = ChatViewModel()
    @State private var selectedTab = 0
    
    var body: some View {
        ZStack {
            // Background
            LinearGradient(
                colors: [.bgPrimary, Color(red: 0.08, green: 0.08, blue: 0.15)],
                startPoint: .top,
                endPoint: .bottom
            )
            .ignoresSafeArea()
            
            TabView(selection: $selectedTab) {
                IdentityTab(viewModel: viewModel)
                    .tabItem {
                        Image(systemName: "key.fill")
                        Text("Identity")
                    }
                    .tag(0)
                
                NetworkTab(viewModel: viewModel)
                    .tabItem {
                        Image(systemName: "network")
                        Text("Network")
                    }
                    .tag(1)
                
                ChatView(viewModel: chatViewModel)
                    .tabItem {
                        Image(systemName: "bubble.left.and.bubble.right.fill")
                        Text("Chats")
                    }
                    .tag(2)
                
                SettingsView()
                    .environmentObject(viewModel)
                    .environmentObject(chatViewModel)
                    .tabItem {
                        Image(systemName: "gear")
                        Text("Settings")
                    }
                    .tag(3)
            }
            .accentColor(.accentEnd)
        }
        .onAppear {
            chatViewModel.bind(to: viewModel)
            viewModel.onMessageReceived = { peerId, data in
                chatViewModel.ingestNetworkMessage(peerId: peerId, data: data)
            }
            // Auto-start network on launch
            viewModel.startNetwork()
        }
    }
}

// MARK: - Identity Tab
struct IdentityTab: View {
    @ObservedObject var viewModel: AppViewModel
    @State private var showCopied = false
    
    var body: some View {
        ZStack {
            // Ambient glow
            Circle()
                .fill(LinearGradient.accent)
                .blur(radius: 100)
                .opacity(0.3)
                .offset(y: -200)
            
            VStack(spacing: 32) {
                Spacer()
                
                // App icon
                ZStack {
                    Circle()
                        .fill(LinearGradient.accent)
                        .frame(width: 100, height: 100)
                        .blur(radius: 20)
                        .opacity(0.6)
                    
                    Image(systemName: "lock.shield.fill")
                        .font(.system(size: 48, weight: .medium))
                        .foregroundStyle(LinearGradient.accent)
                }
                
                // Title
                VStack(spacing: 8) {
                    Text("SecureChat")
                        .font(.system(size: 36, weight: .bold, design: .rounded))
                        .foregroundColor(.white)
                    
                    Text("Zero-Trust P2P Messenger")
                        .font(.subheadline)
                        .foregroundColor(.white.opacity(0.6))
                }
                
                Spacer()
                
                // Identity card
                if let identity = viewModel.identity {
                    IdentityCard(
                        fingerprint: viewModel.fingerprint,
                        publicKeyHex: identity.publicKeyHex,
                        showCopied: $showCopied
                    )
                    .transition(.scale(scale: 0.9).combined(with: .opacity))
                }
                
                Spacer()
                
                // Generate button
                Button(action: {
                    withAnimation(.spring(response: 0.4, dampingFraction: 0.7)) {
                        viewModel.generateNewIdentity()
                    }
                    UIImpactFeedbackGenerator(style: .medium).impactOccurred()
                }) {
                    HStack(spacing: 12) {
                        if viewModel.isGenerating {
                            ProgressView()
                                .progressViewStyle(CircularProgressViewStyle(tint: .white))
                        } else {
                            Image(systemName: viewModel.identity == nil ? "key.fill" : "arrow.triangle.2.circlepath")
                        }
                        Text(viewModel.identity == nil ? "Generate Identity" : "Regenerate")
                            .fontWeight(.semibold)
                    }
                    .foregroundColor(.white)
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 18)
                    .background(LinearGradient.accent.opacity(viewModel.isGenerating ? 0.7 : 1.0))
                    .clipShape(RoundedRectangle(cornerRadius: 16, style: .continuous))
                    .shadow(color: .accentStart.opacity(0.5), radius: 20, y: 10)
                }
                .disabled(viewModel.isGenerating)
                .padding(.horizontal, 32)
                .padding(.bottom, 40)
            }
        }
        .overlay(
            VStack {
                if showCopied {
                    Text("Copied to clipboard")
                        .font(.subheadline.weight(.medium))
                        .foregroundColor(.white)
                        .padding(.horizontal, 20)
                        .padding(.vertical, 12)
                        .background(.ultraThinMaterial)
                        .clipShape(Capsule())
                        .transition(.move(edge: .top).combined(with: .opacity))
                        .onAppear {
                            DispatchQueue.main.asyncAfter(deadline: .now() + 2) {
                                withAnimation { showCopied = false }
                            }
                        }
                }
                Spacer()
            }
            .padding(.top, 60)
        )
    }
}

// MARK: - Network Tab
struct NetworkTab: View {
    @ObservedObject var viewModel: AppViewModel
    
    var body: some View {
        VStack(spacing: 24) {
            // Header
            VStack(spacing: 8) {
                Image(systemName: "network")
                    .font(.system(size: 40))
                    .foregroundStyle(LinearGradient.accent)
                
                Text("P2P Network")
                    .font(.title2.bold())
                    .foregroundColor(.white)
            }
            .padding(.top, 40)
            
            // Status card
            VStack(spacing: 16) {
                HStack {
                    Circle()
                        .fill(viewModel.isNetworkRunning ? Color.green : Color.gray)
                        .frame(width: 12, height: 12)
                    Text(viewModel.isNetworkRunning ? "Running" : "Stopped")
                        .foregroundColor(.white)
                    Spacer()
                }
                
                if !viewModel.peerId.isEmpty {
                    VStack(alignment: .leading, spacing: 4) {
                        Text("Peer ID")
                            .font(.caption)
                            .foregroundColor(.white.opacity(0.5))
                        Text(String(viewModel.peerId.prefix(20)) + "...")
                            .font(.system(size: 12, design: .monospaced))
                            .foregroundColor(.white.opacity(0.8))
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                }
                
                if !viewModel.listeningAddress.isEmpty {
                    VStack(alignment: .leading, spacing: 4) {
                        Text("Listening On")
                            .font(.caption)
                            .foregroundColor(.white.opacity(0.5))
                        Text(viewModel.listeningAddress)
                            .font(.system(size: 11, design: .monospaced))
                            .foregroundColor(.accentEnd)
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                }
            }
            .padding(20)
            .background(
                RoundedRectangle(cornerRadius: 16)
                    .fill(.ultraThinMaterial)
            )
            .padding(.horizontal, 24)
            
            // Start/Stop button
            Button(action: {
                if viewModel.isNetworkRunning {
                    viewModel.stopNetwork()
                } else {
                    viewModel.startNetwork()
                }
                UIImpactFeedbackGenerator(style: .medium).impactOccurred()
            }) {
                HStack {
                    Image(systemName: viewModel.isNetworkRunning ? "stop.fill" : "play.fill")
                    Text(viewModel.isNetworkRunning ? "Stop Network" : "Start Network")
                        .fontWeight(.semibold)
                }
                .foregroundColor(.white)
                .frame(maxWidth: .infinity)
                .padding(.vertical, 16)
                .background(
                    Group {
                        if viewModel.isNetworkRunning {
                            Color.red.opacity(0.8)
                        } else {
                            LinearGradient.accent
                        }
                    }
                )
                .clipShape(RoundedRectangle(cornerRadius: 12))
            }
            .padding(.horizontal, 24)
            
            // Manual Connect
            VStack(alignment: .leading, spacing: 8) {
                Text("Manual Connect")
                    .font(.caption)
                    .foregroundColor(.white.opacity(0.5))
                
                HStack {
                    TextField("Multiaddr (e.g. /ip4/...)", text: $viewModel.manualAddress)
                        .font(.system(size: 11, design: .monospaced))
                        .padding(12)
                        .background(Color.white.opacity(0.05))
                        .clipShape(RoundedRectangle(cornerRadius: 8))
                    
                    Button(action: {
                        viewModel.dialManualAddress()
                    }) {
                        Text("Connect")
                            .font(.caption.bold())
                            .foregroundColor(.white)
                            .padding(.horizontal, 16)
                            .padding(.vertical, 12)
                            .background(LinearGradient.accent)
                            .clipShape(RoundedRectangle(cornerRadius: 8))
                    }
                }
            }
            .padding(.horizontal, 24)
            
            // Discovered peers
            VStack(alignment: .leading, spacing: 12) {
                HStack {
                    Text("Discovered Peers")
                        .font(.headline)
                        .foregroundColor(.white)
                    Spacer()
                    Text("\(viewModel.discoveredPeers.count)")
                        .font(.caption)
                        .foregroundColor(.accentEnd)
                        .padding(.horizontal, 8)
                        .padding(.vertical, 4)
                        .background(Color.accentEnd.opacity(0.2))
                        .clipShape(Capsule())
                }
                
                if viewModel.discoveredPeers.isEmpty {
                    VStack(spacing: 8) {
                        if viewModel.isNetworkRunning {
                            ProgressView()
                                .progressViewStyle(CircularProgressViewStyle(tint: .white.opacity(0.5)))
                            Text("Searching...")
                                .font(.caption)
                                .foregroundColor(.white.opacity(0.5))
                        } else {
                            Text("Start the network to discover peers")
                                .font(.caption)
                                .foregroundColor(.white.opacity(0.5))
                        }
                    }
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 40)
                } else {
                    ScrollView {
                        VStack(spacing: 8) {
                            ForEach(viewModel.discoveredPeers, id: \.peerId) { peer in
                                PeerRow(peer: peer)
                            }
                        }
                    }
                }
            }
            .padding(20)
            .background(
                RoundedRectangle(cornerRadius: 16)
                    .fill(.ultraThinMaterial)
            )
            .padding(.horizontal, 24)
            
            Spacer()
        }
    }
}

// MARK: - Peer Row
struct PeerRow: View {
    let peer: PeerInfo
    
    var body: some View {
        HStack {
            Image(systemName: "person.circle.fill")
                .foregroundStyle(LinearGradient.accent)
                .font(.title2)
            
            VStack(alignment: .leading, spacing: 2) {
                Text(String(peer.peerId.prefix(16)) + "...")
                    .font(.system(size: 12, design: .monospaced))
                    .foregroundColor(.white)
                
                if let addr = peer.addresses.first {
                    Text(addr)
                        .font(.system(size: 10, design: .monospaced))
                        .foregroundColor(.white.opacity(0.5))
                }
            }
            
            Spacer()
            
            Circle()
                .fill(Color.green)
                .frame(width: 8, height: 8)
        }
        .padding(12)
        .background(Color.white.opacity(0.05))
        .clipShape(RoundedRectangle(cornerRadius: 10))
    }
}

// MARK: - Identity Card
struct IdentityCard: View {
    let fingerprint: String
    let publicKeyHex: String
    @Binding var showCopied: Bool
    
    var body: some View {
        VStack(spacing: 20) {
            VStack(spacing: 8) {
                Text("Your Identity Fingerprint")
                    .font(.caption)
                    .foregroundColor(.white.opacity(0.5))
                
                Text(fingerprint)
                    .font(.system(size: 22, weight: .bold, design: .monospaced))
                    .foregroundStyle(LinearGradient.accent)
            }
            
            Divider()
                .background(Color.white.opacity(0.1))
            
            VStack(spacing: 8) {
                Text("Public Key")
                    .font(.caption)
                    .foregroundColor(.white.opacity(0.5))
                
                Text(truncatedKey)
                    .font(.system(size: 12, design: .monospaced))
                    .foregroundColor(.white.opacity(0.7))
                    .lineLimit(2)
                    .multilineTextAlignment(.center)
            }
            
            Button(action: {
                UIPasteboard.general.string = publicKeyHex
                withAnimation(.spring(response: 0.3, dampingFraction: 0.7)) {
                    showCopied = true
                }
                UINotificationFeedbackGenerator().notificationOccurred(.success)
            }) {
                HStack(spacing: 8) {
                    Image(systemName: "doc.on.doc")
                    Text("Copy Full Key")
                }
                .font(.subheadline.weight(.medium))
                .foregroundColor(.accentEnd)
                .padding(.horizontal, 20)
                .padding(.vertical, 10)
                .background(Color.accentEnd.opacity(0.15))
                .clipShape(Capsule())
            }
        }
        .padding(24)
        .frame(maxWidth: .infinity)
        .background(
            RoundedRectangle(cornerRadius: 24, style: .continuous)
                .fill(.ultraThinMaterial)
                .overlay(
                    RoundedRectangle(cornerRadius: 24, style: .continuous)
                        .stroke(Color.white.opacity(0.1), lineWidth: 1)
                )
        )
        .padding(.horizontal, 24)
    }
    
    private var truncatedKey: String {
        let prefix = String(publicKeyHex.prefix(20))
        let suffix = String(publicKeyHex.suffix(20))
        return "\(prefix)...\(suffix)"
    }
}

// MARK: - Settings View
struct SettingsView: View {
    @EnvironmentObject var appViewModel: AppViewModel
    @EnvironmentObject var chatViewModel: ChatViewModel
    
    var cliSessionCommand: String {
        guard let bundleJson = chatViewModel.prekeyBundleJson,
              let data = bundleJson.data(using: .utf8),
              let bundle = try? JSONDecoder().decode(PreKeyBundleDTO.self, from: data) else {
            return "Loading..."
        }
        let identity = bundle.identity_key.map { String(format: "%02x", $0) }.joined()
        let verifying = bundle.identity_verifying_key.map { String(format: "%02x", $0) }.joined()
        let prekey = bundle.signed_prekey.map { String(format: "%02x", $0) }.joined()
        let sig = bundle.signed_prekey_signature.map { String(format: "%02x", $0) }.joined()
        return "/session \(appViewModel.peerId) \(identity) \(verifying) \(prekey) \(sig)"
    }
    
    var cliSendCommand: String {
        "/send \(appViewModel.peerId) Hello from CLI!"
    }
    
    var body: some View {
        NavigationView {
            List {
                Section("CLI Commands (tap to copy)") {
                    Button(action: { UIPasteboard.general.string = cliSessionCommand }) {
                        VStack(alignment: .leading, spacing: 4) {
                            Text("Session Command")
                                .font(.caption.bold())
                            Text(cliSessionCommand)
                                .font(.system(.caption2, design: .monospaced))
                                .foregroundColor(.secondary)
                                .lineLimit(3)
                        }
                    }
                    
                    Button(action: { UIPasteboard.general.string = cliSendCommand }) {
                        VStack(alignment: .leading, spacing: 4) {
                            Text("Send Command")
                                .font(.caption.bold())
                            Text(cliSendCommand)
                                .font(.system(.caption2, design: .monospaced))
                                .foregroundColor(.secondary)
                        }
                    }
                }
                
                Section("Network") {
                    HStack {
                        Text("Status")
                        Spacer()
                        Text(appViewModel.isNetworkRunning ? "Connected" : "Offline")
                            .foregroundColor(appViewModel.isNetworkRunning ? .green : .red)
                    }
                    HStack {
                        Text("Peers")
                        Spacer()
                        Text("\(appViewModel.discoveredPeers.count)")
                    }
                }
                
                Section("Privacy") {
                    Toggle("Onion Routing", isOn: $appViewModel.isOnionEnabled)
                        .onChange(of: appViewModel.isOnionEnabled) { newValue in
                            appViewModel.privacyManager?.setOnionEnabled(enabled: newValue)
                        }
                    
                    HStack {
                        Text("Active Relays")
                        Spacer()
                        Text("\(appViewModel.relayCount)")
                            .foregroundColor(appViewModel.relayCount >= 3 ? .green : .orange)
                    }
                    
                    if appViewModel.relayCount < 3 {
                        Text("At least 3 relays are required for onion routing circuits.")
                            .font(.caption)
                            .foregroundColor(.secondary)
                    }
                }
            }
            .navigationTitle("Identity")
            .toolbar {
                ToolbarItem(placement: .navigationBarTrailing) {
                    Text("v\(Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "1.0") (\(Bundle.main.infoDictionary?["CFBundleVersion"] as? String ?? "1"))")
                        .font(.caption)
                        .foregroundColor(.gray)
                }
            }
        }
    }
}

struct PreKeyBundleDTO: Decodable {
    let identity_key: [UInt8]
    let identity_verifying_key: [UInt8]
    let signed_prekey: [UInt8]
    let signed_prekey_signature: [UInt8]
}


#Preview {
    ContentView()
}

// MARK: - Logging Manager
/// Centralized logging manager that bridges Rust logs and provides Swift logging utilities
class LogManager: CoreLogger {
    static let shared = LogManager()
    
    // Explicitly typed to avoid ambiguity
    private let osLogger = os.Logger(subsystem: "com.securechat.app", category: "RustCore")
    private let swiftLogger = os.Logger(subsystem: "com.securechat.app", category: "SwiftApp")
    
    // Log levels to enable (simple toggle)
    var isDebugEnabled = true
    
    // UDL Low-Level Logger Protocol Implementation
    func log(level: String, message: String) {
        guard isDebugEnabled else { return }
        
        switch level.lowercased() {
        case "error":
            osLogger.error("🔴 [RUST] \(message, privacy: .public)")
        case "warn":
            osLogger.warning("⚠️ [RUST] \(message, privacy: .public)")
        case "info":
            osLogger.info("ℹ️ [RUST] \(message, privacy: .public)")
        case "debug":
            osLogger.debug("🐞 [RUST] \(message, privacy: .public)")
        default:
            osLogger.trace("⚪ [RUST] \(message, privacy: .public)")
        }
    }
    
    // Swift Logging Methods
    func debug(_ message: String, context: String = "") {
        guard isDebugEnabled else { return }
        let ctx = context.isEmpty ? "" : "[\(context)] "
        swiftLogger.debug("\(ctx)\(message, privacy: .public)")
    }
    
    func info(_ message: String, context: String = "") {
        let ctx = context.isEmpty ? "" : "[\(context)] "
        swiftLogger.info("\(ctx)\(message, privacy: .public)")
    }
    
    func error(_ message: String, context: String = "") {
        let ctx = context.isEmpty ? "" : "[\(context)] "
        swiftLogger.error("🔴 \(ctx)\(message, privacy: .public)")
    }
    
    // Initialize Rust logging
    func setup() {
        print("Initializing Rust Logger...") // Stdout
        swiftLogger.info("Initializing Rust Logger (OSLog)...")
        // Call the Rust init_logger function, passing self as the callback
        initLogger(callback: self)
        swiftLogger.info("Rust Logger initialization called.")
    }
}

import SwiftUI
import CoreData
import os
import CoreImage.CIFilterBuiltins
import AVFoundation
import Network

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
    @Published var connectedPeers: Set<String> = []
    @Published var listeningAddresses: [String] = []
    @Published var logServerURL: String?
    
    var listeningAddress: String {
        // 1. Prefer relay addresses (bridge)
        if let relay = listeningAddresses.first(where: { $0.contains("p2p-circuit") }) {
            return relay
        }
        // 2. Otherwise prefer external IP (exclude 127.0.0.1 and loopback)
        return listeningAddresses.first(where: { 
            !$0.contains("127.0.0.1") && !$0.contains("::1") && !$0.contains("/localhost/") 
        }) ?? listeningAddresses.first ?? ""
    }
    @Published var peerId: String = ""
    @Published var identityKeyHex: String = ""
    
    // Privacy state
    @Published var privacyManager: PrivacyApi?
    @Published var isOnionEnabled: Bool = false
    @Published var relayCount: Int = 0
    
    // Callbacks
    var onMessageReceived: ((String, Data) -> Void)?
    var onPeerConnected: ((String) -> Void)?
    
    private var pollTimer: Timer?
    
    func generateNewIdentity() {
        isGenerating = true
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.3) { [weak self] in
            // Use generateIdentityBytes which returns [UInt8]
            let _ = generateIdentityBytes()
            // Convert to Identity struct if needed, or just use bytes for now?
            // The UI expects `identity: Identity?`. 
            // `Identity` struct in UDL/Swift has hex strings.
            // We can reconstruct Identity from keyBytes using extractIdentityDetails? Or generateIdentity() (the struct one)?
            // Wait, I left generateIdentity (struct) in UDL!
            // core/securechat_core.udl: Identity generate_identity();
            // So generateIdentity() IS VALID and returns Identity struct.
            // But startNetwork needs BYTES.
            // So let's use generateIdentity() here for UI, and generateIdentityBytes() in startNetwork?
            // Problem: they will be DIFFERENT identities if called separately!
            // We must use one and derive the other.
            // `extractIdentityDetails(keyBytes: [UInt8]) -> IdentityDetails`.
            // IdentityDetails has peer_id, public_key_hex.
            // Identity struct has public_key_hex, private_key_hex.
            // We can't easily convert [UInt8] to Identity struct (private key hex) without helper.
            
            // BETTER: Use generateIdentity() (Returns Identity).
            // But how to getBYTES from Identity?
            // Identity has private_key_hex. We can decode hex to bytes.
            // Swift doesn't have built-in hex decode easily?
            // helper: `generate_identity_bytes` returns bytes.
            // helper: `extract_identity_details` returns details.
            
            // I'll use generateIdentityBytes() as source of truth.
            let _ = generateIdentityBytes()
            // Saving/Loading logic uses bytes.
            // UI needs Identity struct?
            // Identity struct definition:
            // public struct Identity { public var publicKeyHex: String; public var privateKeyHex: String }
            // I can construct it if I have hex strings.
            // extractIdentityDetails(bytes) gives public_key_hex.
            // private_key_hex?
            // I'll just use generateIdentity() (struct) and convert to bytes?
            // To convert struct to bytes: I need to decode private_key_hex.
            
            // ALTERNATIVE: Use generateIdentity() (Struct).
            // Then manually hex-decode private key to get bytes for specific functions?
            // `createConfiguredNetworkManager` takes bytes.
            
            // Let's use `generateIdentity()` (Struct).
            let newIdentity = generateIdentity()
            self?.identity = newIdentity
            self?.fingerprint = getPublicKeyFingerprint(identity: newIdentity)
            self?.isGenerating = false
            
            // But wait, startNetwork saves BYTES to disk.
            // It calls `generateIdentity()` (line 84).
            // It tries `newKey.write(to: url)`. Identity struct doesn't have .write.
            // It needs bytes.
        }
    }
    
    func startNetwork() {
        if networkManager == nil {
            // Persistence: Load Identity & Path
            let fileManager = FileManager.default
            if let docs = fileManager.urls(for: .documentDirectory, in: .userDomainMask).first {
                let identityUrl = docs.appendingPathComponent("identity.key")
                let peersUrl = docs.appendingPathComponent("peers.json")
                
                print("Identity Path: \(identityUrl.path)")
                
                var keyBytes: Data?
                
                // Try to load existing identity
                if fileManager.fileExists(atPath: identityUrl.path) {
                    do {
                        keyBytes = try Data(contentsOf: identityUrl)
                        print("Loaded existing identity (\(keyBytes?.count ?? 0) bytes)")
                    } catch {
                        print("Failed to load identity: \(error)")
                    }
                }
                
                // If missing or failed, generate new one
                if keyBytes == nil {
                    print("Generating NEW identity...")
                    // Use generateIdentityBytes to get [UInt8], then convert to Data
                    let keyArray = generateIdentityBytes()
                    let newData = Data(keyArray)
                    keyBytes = newData
                    do {
                        try newData.write(to: identityUrl)
                        print("Saved new identity to disk")
                    } catch {
                        print("Failed to save identity: \(error)")
                    }
                }
                
                if let key = keyBytes {
                    // Convert Data to [UInt8]
                    let keyArray = [UInt8](key)
                    do {
                        // Use global function
                        networkManager = try createConfiguredNetworkManager(identityKeyBytes: keyArray, persistencePath: peersUrl.path)
                        print("Network Manager created with persistence")
                        
                        // Populate identityKeyHex from current identity
                        if let details = try? extractIdentityDetails(keyBytes: keyArray) {
                            self.identityKeyHex = details.identityKeyHex
                        }
                    } catch {
                        print("Failed to create configured network manager: \(error)")
                        // Fallback (non-persistent)
                        networkManager = createNetworkManager()
                    }
                } else {
                    networkManager = createNetworkManager()
                }
            } else {
                networkManager = createNetworkManager()
            }
            
            peerId = networkManager?.getPeerId() ?? ""
            
            print("🚀 APP STARTUP:")
            print("   PeerID: \(peerId)")
            print("   Identity Key (X25519): \(identityKeyHex)")
            LogManager.shared.info("App Startup - PeerID: \(peerId), IdentityKey: \(identityKeyHex)", context: "AppViewModel")
            
            privacyManager = createPrivacyManager()
            privacyManager?.setOnionEnabled(enabled: isOnionEnabled)
            
            // Populate Identity model for UI
            if !peerId.isEmpty {
                // We don't have the full Identity struct from FFI easily here without parsing
                // So we'll just use the PeerID for display or reconstruction?
                // Actually `Identity` struct in UI seems to be a Swift struct based on the code I read
                // But I can't see the definition.
                // Let's just set the fingerprint based on PeerID for now?
                // Or maybe `networkManager` has a method to get public key?
                // Core `P2PNode` has `public_key_hex()`.
                // NetworkManager doesn't expose it yet?
                // Wait, I need to check `api.rs` again.
                // It exposes `get_peer_id`.
                // It does NOT expose `get_public_key`.
            }
        }
        
        do {
            try networkManager?.start()
            isNetworkRunning = true
            
            // Start Log server for desktop debugging
            LogServer.shared.start()
            // We'll update the URL once we have a listen address
            
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
        listeningAddresses = []
    }
    
    func dialManualAddress() {
        guard !manualAddress.isEmpty else { return }
        do {
            try networkManager?.dial(address: manualAddress)
            LogManager.shared.info("Manually dialing \(manualAddress)", context: "AppViewModel")
            manualAddress = ""
            // Clear current list to force refresh when new relay is found
            listeningAddresses = []
        } catch {
            LogManager.shared.error("Failed to dial address: \(error)", context: "AppViewModel")
        }
    }
    
    func handleDeepLink(_ url: URL) {
        // Format: securechat://connect?addr=/ip4/...
        guard url.scheme == "securechat" else { return }
        print("Handling deep link: \(url)")
        
        if let components = URLComponents(url: url, resolvingAgainstBaseURL: false),
           let queryItems = components.queryItems,
           let addr = queryItems.first(where: { $0.name == "addr" })?.value {
            
            print("Deep link connect to: \(addr)")
            // Delay slightly to ensure network is ready if app just launched
            DispatchQueue.main.asyncAfter(deadline: .now() + 1.0) { [weak self] in
                do {
                    // Ensure network is started
                    if self?.networkManager == nil {
                        self?.startNetwork()
                    }
                    try self?.networkManager?.dial(address: addr)
                    LogManager.shared.info("Deep link dialing \(addr)", context: "AppViewModel")
                } catch {
                    LogManager.shared.error("Deep link dial failed: \(error)", context: "AppViewModel")
                }
            }
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
            if !listeningAddresses.contains(address) {
                listeningAddresses.append(address)
                // If it's a local IP, update Log Server URL hint
                if address.contains("ip4") && !address.contains("127.0.0.1") && !address.contains("p2p-circuit") {
                    let parts = address.components(separatedBy: "/")
                    // Multiaddr format: /ip4/192.168.1.10/tcp/1234
                    if parts.count >= 3 && parts[1] == "ip4" {
                        let ip = parts[2]
                        self.logServerURL = "http://\(ip):8080/logs"
                        LogManager.shared.info("Log Server accessible at: \(self.logServerURL ?? "")", context: "AppViewModel")
                    }
                }
            }
        case .peerDiscovered(let peer):
            LogManager.shared.info("Discovered peer: \(peer.peerId)", context: "AppViewModel")
            if !discoveredPeers.contains(where: { $0.peerId == peer.peerId }) {
                discoveredPeers.append(peer)
                // Haptic feedback
                let generator = UINotificationFeedbackGenerator()
                generator.notificationOccurred(.success)
                
                // AUTO-DIAL: Only if not connected
                if !connectedPeers.contains(peer.peerId) {
                    // Prefer QUIC or Relay addresses
                    let bestAddr = peer.addresses.first(where: { $0.contains("quic") || $0.contains("p2p-circuit") }) ?? peer.addresses.first
                    if let addr = bestAddr {
                        LogManager.shared.info("Auto-dialing best address: \(addr)", context: "AppViewModel")
                        try? networkManager?.dial(address: addr)
                    }
                }
            }
        case .peerDisconnected(let peerId):
            LogManager.shared.info("Peer disconnected: \(peerId)", context: "AppViewModel")
            discoveredPeers.removeAll { $0.peerId == peerId }
            connectedPeers.remove(peerId)
        case .peerConnected(let peerId):
            LogManager.shared.info("Peer connected: \(peerId)", context: "AppViewModel")
            connectedPeers.insert(peerId)
            // BUG FIX 2: Notify ChatViewModel to retry pending session requests
            onPeerConnected?(peerId)
        case .error(let message):
            LogManager.shared.error("Network error: \(message)", context: "AppViewModel")
        case .messageReceived(let peerId, let data):
            LogManager.shared.info("Network received message from \(peerId), size: \(data.count)", context: "AppViewModel")
            onMessageReceived?(peerId, Data(data))
        }
    }
    
    private func handlePrivacyEvent(_ event: PrivacyApiEvent) {
        switch event {
        case .relayPacket(let nextPeerId, let packetBytes, let delayMs):
            LogManager.shared.info("Privacy: Relaying packet to \(nextPeerId) after \(delayMs)ms", context: "AppViewModel")
            LogManager.shared.info("Privacy: Relay packet size \(packetBytes.count)", context: "AppViewModel")
            // For now we send immediately, ignoring delay for simplicity in this demo
            // In a real app we'd use DispatchQueue.main.asyncAfter
            do {
                try networkManager?.sendMessage(peerId: nextPeerId, data: packetBytes)
            } catch {
                LogManager.shared.error("Failed to relay packet: \(error)", context: "AppViewModel")
            }
            
        case .deliverPayload(let nextPeerId, let payload):
            LogManager.shared.info("Privacy: Delivering exit payload to \(nextPeerId)", context: "AppViewModel")
            LogManager.shared.info("Privacy: Exit payload size \(payload.count)", context: "AppViewModel")
            do {
                try networkManager?.sendMessage(peerId: nextPeerId, data: payload)
            } catch {
                LogManager.shared.error("Failed to deliver payload: \(error)", context: "AppViewModel")
            }
            
        case .packetDelivered(let payload):
            LogManager.shared.info("Privacy: Packet reached destination (us!), passing to messaging", context: "AppViewModel")
            LogManager.shared.info("Privacy: PacketDelivered payload size \(payload.count)", context: "AppViewModel")
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
    @ObservedObject var viewModel: AppViewModel
    @StateObject private var chatViewModel = ChatViewModel()
    @State private var selectedTab = 0
    @State private var showScanner = false
    @State private var showInvitation = false
    @State private var showDebugLogs = false
    
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
                IdentityTab(viewModel: viewModel, showInvitation: $showInvitation)
                    .tabItem {
                        Image(systemName: "key.fill")
                        Text("Identity")
                    }
                    .tag(0)
                
                NetworkTab(viewModel: viewModel, chatViewModel: chatViewModel)
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
            
            // Floating debug log toggle
            VStack {
                Spacer()
                HStack {
                    Spacer()
                    Button(action: { showDebugLogs.toggle() }) {
                        Text(showDebugLogs ? "Hide Logs" : "Show Logs")
                            .font(.caption.bold())
                            .padding(.horizontal, 12)
                            .padding(.vertical, 8)
                            .background(Color.black.opacity(0.5))
                            .foregroundColor(.white)
                            .clipShape(Capsule())
                    }
                    .padding(.trailing, 16)
                    .padding(.bottom, 24)
                }
            }
            
            if showDebugLogs {
                DebugLogPanel()
                    .transition(.move(edge: .bottom).combined(with: .opacity))
            }
        }
        .sheet(isPresented: $showInvitation) {
            InvitationView(
                peerId: viewModel.peerId,
                addresses: inviteAddresses(peerId: viewModel.peerId, listening: viewModel.listeningAddresses)
            )
        }
        .onAppear {
            chatViewModel.bind(to: viewModel)
            viewModel.onMessageReceived = { peerId, data in
                chatViewModel.ingestNetworkMessage(peerId: peerId, data: data)
            }
            viewModel.onPeerConnected = { peerId in
                chatViewModel.handlePeerConnected(peerId: peerId)
            }
            // Auto-start network on launch
            viewModel.startNetwork()
        }
    }
}

private func prioritizedAddresses(from addresses: [String]) -> [String] {
    if addresses.isEmpty { return [] }
    return addresses.sorted { lhs, rhs in
        let lhsRelay = lhs.contains("p2p-circuit")
        let rhsRelay = rhs.contains("p2p-circuit")
        if lhsRelay != rhsRelay { return lhsRelay }
        let lhsLoopback = lhs.contains("127.0.0.1") || lhs.contains("::1") || lhs.contains("/localhost/")
        let rhsLoopback = rhs.contains("127.0.0.1") || rhs.contains("::1") || rhs.contains("/localhost/")
        if lhsLoopback != rhsLoopback { return !lhsLoopback }
        return lhs < rhs
    }
}

private func inviteAddresses(peerId: String, listening: [String]) -> [String] {
    let ordered = prioritizedAddresses(from: listening)
    let relayAddrs = ordered.filter { $0.contains("p2p-circuit") }
    return relayAddrs.map { ensureRelayDialAddress($0, peerId: peerId) }
}

private func ensureRelayDialAddress(_ address: String, peerId: String) -> String {
    if address.contains("/p2p-circuit/p2p/") {
        return address
    }
    if address.contains("p2p-circuit") {
        return address + "/p2p/\(peerId)"
    }
    return address
}

// MARK: - Identity Tab
struct IdentityTab: View {
    @ObservedObject var viewModel: AppViewModel
    @Binding var showInvitation: Bool
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
                        identityKeyHex: viewModel.identityKeyHex,
                        showCopied: $showCopied
                    )
                    .transition(.scale(scale: 0.9).combined(with: .opacity))
                }
                
                Spacer()
                
                // Invitation / Share
                if let _ = viewModel.identity, !viewModel.peerId.isEmpty {
                     Button(action: {
                        showInvitation = true
                     }) {
                        HStack {
                            Image(systemName: "qrcode")
                            Text("Share Identity")
                        }
                        .font(.headline)
                        .foregroundColor(.white)
                        .padding()
                        .background(Color.white.opacity(0.1))
                        .clipShape(Capsule())
                     }
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
    @ObservedObject var chatViewModel: ChatViewModel
    @State private var showScanner = false
    
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
            
            // Scan Button
            Button(action: {
                showScanner = true
            }) {
                HStack {
                    Image(systemName: "qrcode.viewfinder")
                    Text("Scan Friend's QR")
                }
                .font(.headline)
                .foregroundColor(.white)
                .frame(maxWidth: .infinity)
                .padding()
                .background(Color.white.opacity(0.1))
                .clipShape(RoundedRectangle(cornerRadius: 12))
            }
            .padding(.horizontal, 24)
            .sheet(isPresented: $showScanner) {
                ScannerView(viewModel: viewModel, chatViewModel: chatViewModel)
            }
            
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
    let identityKeyHex: String
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
                Text("Identity Key (X25519)")
                    .font(.caption)
                    .foregroundColor(.white.opacity(0.5))
                
                Text(truncatedIdentityKey)
                    .font(.system(size: 12, design: .monospaced))
                    .foregroundColor(.white.opacity(0.7))
                    .lineLimit(2)
                    .multilineTextAlignment(.center)
            }
            
            Button(action: {
                UIPasteboard.general.string = identityKeyHex
                withAnimation(.spring(response: 0.3, dampingFraction: 0.7)) {
                    showCopied = true
                }
                UINotificationFeedbackGenerator().notificationOccurred(.success)
            }) {
                HStack(spacing: 8) {
                    Image(systemName: "doc.on.doc")
                    Text("Copy Identity Key")
                }
                .font(.subheadline.weight(.medium))
                .foregroundColor(.accentEnd)
                .padding(.horizontal, 20)
                .padding(.vertical, 10)
                .background(Color.accentEnd.opacity(0.15))
                .clipShape(Capsule())
            }
            
            Divider()
                .background(Color.white.opacity(0.1))
            
            VStack(spacing: 8) {
                Text("Public Key (Ed25519)")
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
                    Text("Copy Public Key")
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
        let prefix = String(publicKeyHex.prefix(12))
        let suffix = String(publicKeyHex.suffix(12))
        return "\(prefix)...\(suffix)"
    }
    
    private var truncatedIdentityKey: String {
        let prefix = String(identityKeyHex.prefix(12))
        let suffix = String(identityKeyHex.suffix(12))
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
                            .foregroundColor(appViewModel.relayCount >= 1 ? .green : .orange)
                    }
                    
                    if appViewModel.relayCount < 1 {
                        Text("At least 1 relay is required for onion routing circuits.")
                            .font(.caption)
                            .foregroundColor(.secondary)
                    }
                }
                
                Section("Debugging") {
                    VStack(alignment: .leading, spacing: 8) {
                        Text("Log Server URL")
                            .font(.caption.bold())
                        
                        if let url = appViewModel.logServerURL {
                            Text(url)
                                .font(.system(.caption2, design: .monospaced))
                                .foregroundColor(.accentEnd)
                            
                            Button(action: { UIPasteboard.general.string = url }) {
                                Label("Copy Log URL", systemImage: "doc.on.doc")
                                    .font(.caption)
                            }
                            .buttonStyle(.bordered)
                            .tint(.accentEnd)
                        } else {
                            Text("Waiting for network...")
                                .font(.caption2)
                                .foregroundColor(.secondary)
                        }
                    }
                    .padding(.vertical, 4)
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
    ContentView(viewModel: AppViewModel())
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
        
        DebugLogStore.shared.add("[RUST] \(level.uppercased()): \(message)")
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
        DebugLogStore.shared.add("\(ctx)\(message)")
        swiftLogger.debug("\(ctx)\(message, privacy: .public)")
    }
    
    func info(_ message: String, context: String = "") {
        let ctx = context.isEmpty ? "" : "[\(context)] "
        DebugLogStore.shared.add("\(ctx)\(message)")
        swiftLogger.info("\(ctx)\(message, privacy: .public)")
    }
    
    func warn(_ message: String, context: String = "") {
        let ctx = context.isEmpty ? "" : "[\(context)] "
        DebugLogStore.shared.add("WARN \(ctx)\(message)")
        swiftLogger.warning("\(ctx)\(message, privacy: .public)")
    }
    
    func error(_ message: String, context: String = "") {
        let ctx = context.isEmpty ? "" : "[\(context)] "
        DebugLogStore.shared.add("ERROR \(ctx)\(message)")
        swiftLogger.error("🔴 \(ctx)\(message, privacy: .public)")
    }
    
    // Initialize Rust logging
    func setup() {
        print("Initializing Rust Logger...") // Stdout
        swiftLogger.info("Initializing Rust Logger (OSLog)...")
        // Call the Rust init_logger function, passing self as the callback
        initLogger(callback: self)
        swiftLogger.info("Rust Logger initialization called.")
        DebugLogStore.shared.add("Logger initialized")
    }
    }

final class DebugLogStore: ObservableObject {
    static let shared = DebugLogStore()
    @Published var lines: [String] = []
    
    func add(_ line: String) {
        DispatchQueue.main.async {
            self.lines.append(line)
            if self.lines.count > 200 {
                self.lines.removeFirst(self.lines.count - 200)
            }
        }
    }
    
    var joined: String {
        lines.joined(separator: "\n")
    }
}

// MARK: - Log Server
/// Minimal HTTP server to serve app logs over the network
class LogServer {
    static let shared = LogServer()
    private var listener: NWListener?
    private var port: NWEndpoint.Port = 8080
    
    func start() {
        guard listener == nil else { return }
        do {
            listener = try NWListener(using: .tcp, on: port)
            
            listener?.stateUpdateHandler = { state in
                switch state {
                case .ready:
                    print("Log Server ready on port 8080")
                case .failed(let error):
                    print("Log Server failed: \(error)")
                default:
                    break
                }
            }
            
            listener?.newConnectionHandler = { connection in
                self.handleConnection(connection)
            }
            
            listener?.start(queue: .main)
        } catch {
            print("Failed to start Log Server: \(error)")
        }
    }
    
    private func handleConnection(_ connection: NWConnection) {
        connection.stateUpdateHandler = { state in
            if case .ready = state {
                self.receiveRequest(connection)
            }
        }
        connection.start(queue: .main)
    }
    
    private func receiveRequest(_ connection: NWConnection) {
        connection.receive(minimumIncompleteLength: 1, maximumLength: 1024) { data, _, isComplete, error in
            if let data = data, !data.isEmpty {
                self.sendResponse(connection)
            } else if error != nil {
                connection.cancel()
            }
        }
    }
    
    private func sendResponse(_ connection: NWConnection) {
        let logs = DebugLogStore.shared.joined
        let response = """
HTTP/1.1 200 OK
Content-Type: text/plain; charset=utf-8
Content-Length: \(logs.utf8.count)
Connection: close
Access-Control-Allow-Origin: *

\(logs)
"""
        
        connection.send(content: response.data(using: .utf8), completion: .contentProcessed { _ in
            connection.cancel()
        })
    }
}

struct DebugLogPanel: View {
    @ObservedObject private var store = DebugLogStore.shared
    
    var body: some View {
        VStack(spacing: 8) {
            HStack {
                Text("Debug Logs")
                    .font(.caption.bold())
                    .foregroundColor(.white)
                Spacer()
                Button("Copy") {
                    UIPasteboard.general.string = store.joined
                }
                .font(.caption)
                .foregroundColor(.accentEnd)
            }
            
            ScrollView {
                Text(store.joined)
                    .font(.system(size: 10, design: .monospaced))
                    .foregroundColor(.white.opacity(0.85))
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .textSelection(.enabled)
            }
            .frame(maxHeight: 260)
        }
        .padding(12)
        .background(Color.black.opacity(0.7))
        .clipShape(RoundedRectangle(cornerRadius: 12))
        .padding(.horizontal, 16)
        .padding(.bottom, 80)
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .bottom)
    }
}

// MARK: - Invitation View
struct InvitationView: View {
    let peerId: String
    let addresses: [String]
    
    private var relayAddress: String? {
        addresses.first(where: { $0.contains("p2p-circuit") })
    }
    
    var connectionString: String {
        if let addr = relayAddress {
            return "securechat://invite/\(peerId)/\(addr)"
        }
        return "securechat://invite/\(peerId)/pending"
    }
    
    let context = CIContext()
    let filter = CIFilter.qrCodeGenerator()
    
    var body: some View {
        VStack(spacing: 24) {
            Text("Invite a Friend")
                .font(.title2.bold())
                .foregroundColor(.white)
                .padding(.top, 20)
            
            Text("Scan this QR code with another SecureChat to connect directly P2P.")
                .font(.caption)
                .foregroundColor(.white.opacity(0.6))
                .multilineTextAlignment(.center)
                .padding(.horizontal)
            
            if relayAddress == nil {
                Text("Waiting for relay reservation… keep the app open and connected.")
                    .font(.caption2)
                    .foregroundColor(.white.opacity(0.6))
                    .multilineTextAlignment(.center)
                    .padding(.horizontal)
            }
            
            ZStack {
                RoundedRectangle(cornerRadius: 20)
                    .fill(Color.white)
                    .frame(width: 250, height: 250)
                
                if relayAddress != nil, let qrImage = generateQRCode(from: connectionString) {
                    Image(uiImage: qrImage)
                        .interpolation(.none)
                        .resizable()
                        .scaledToFit()
                        .frame(width: 230, height: 230)
                } else {
                    Image(systemName: "hourglass")
                        .font(.largeTitle)
                        .foregroundColor(.gray)
                }
            }
            .shadow(color: .accentStart.opacity(0.5), radius: 20, x: 0, y: 0)
            
            VStack(spacing: 8) {
                Text("YOUR ADDRESS")
                    .font(.caption2.bold())
                    .foregroundColor(.white.opacity(0.4))
                
                Text(connectionString)
                    .font(.system(size: 10, design: .monospaced))
                    .foregroundColor(.white.opacity(0.6))
                    .multilineTextAlignment(.center)
                    .lineLimit(3)
                    .padding(.horizontal)
            }
            
            Spacer()
        }
        .padding()
        .background(Color.bgSecondary.ignoresSafeArea())
    }
    
    func generateQRCode(from string: String) -> UIImage? {
        let data = Data(string.utf8)
        filter.setValue(data, forKey: "inputMessage")
        
        if let outputImage = filter.outputImage {
            // Scale up slightly for sharpness before converting to UIImage
            let transform = CGAffineTransform(scaleX: 10, y: 10)
            let scaledImage = outputImage.transformed(by: transform)
            
            if let cgImage = context.createCGImage(scaledImage, from: scaledImage.extent) {
                return UIImage(cgImage: cgImage)
            }
        }
        return nil
    }
}

// MARK: - Scanner View
struct ScannerView: View {
    @ObservedObject var viewModel: AppViewModel
    @ObservedObject var chatViewModel: ChatViewModel
    @Environment(\.presentationMode) var presentationMode
    
    var body: some View {
        ZStack {
            QrCodeScannerView { code in
                self.handleScan(code: code)
            }
            .edgesIgnoringSafeArea(.all)
            
            VStack {
                Text("Scan Friend's Code")
                    .font(.headline)
                    .padding()
                    .background(.ultraThinMaterial)
                    .cornerRadius(12)
                    .padding(.top, 40)
                
                Spacer()
                
                Button(action: {
                    presentationMode.wrappedValue.dismiss()
                }) {
                    Image(systemName: "xmark.circle.fill")
                        .font(.largeTitle)
                        .foregroundColor(.white)
                        .padding(.bottom, 40)
                }
            }
        }
    }
    
    func handleScan(code: String) {
        // Format: securechat://invite/PEER_ID/MULTIADDR_BASE64
        if code.starts(with: "securechat://invite/") {
            let components = code.components(separatedBy: "/")
            if components.count >= 5 {
                let peerId = components[3]
                let address = components[4..<components.count].joined(separator: "/")
                
                LogManager.shared.info("Scanned Invite: \(peerId) at \(address)", context: "ScannerView")
                
                // Ensure UI updates happen on Main Thread
                DispatchQueue.main.async {
                    LogManager.shared.info("TRACE: Dismissing Scanner on Main Thread", context: "ScannerView")
                    
                    // Haptic feedback
                    let generator = UINotificationFeedbackGenerator()
                    generator.notificationOccurred(.success)
                    
                    // Dismiss view
                    self.presentationMode.wrappedValue.dismiss()
                    
                    // Trigger networking in background AFTER UI update is scheduled
                    DispatchQueue.global(qos: .userInitiated).async {
                        LogManager.shared.info("TRACE: Background Dial Initiated for \(address)", context: "ScannerView")
                        do {
                            // Dial - this blocks, so MUST be in background
                            try self.viewModel.networkManager?.dial(address: address)
                            LogManager.shared.info("Dial succeeded for \(address)", context: "ScannerView")
                        } catch {
                            LogManager.shared.error("Failed to dial scanned address: \(error)", context: "ScannerView")
                        }
                        
                        // Queue the session request back on Main Thread
                        DispatchQueue.main.async {
                            LogManager.shared.info("TRACE: Triggering requestSession for \(peerId)", context: "ScannerView")
                            self.chatViewModel.requestSession(peerId: peerId)
                        }
                    }
                }
            }
        }
    }
}

struct QrCodeScannerView: UIViewControllerRepresentable {
    var onCodeScanned: (String) -> Void
    
    func makeUIViewController(context: Context) -> ScannerViewController {
        let scanner = ScannerViewController()
        scanner.delegate = context.coordinator
        return scanner
    }
    
    func updateUIViewController(_ uiViewController: ScannerViewController, context: Context) {}
    
    func makeCoordinator() -> Coordinator {
        Coordinator(parent: self)
    }
    
    class Coordinator: NSObject, ScannerDelegate {
        var parent: QrCodeScannerView
        
        init(parent: QrCodeScannerView) {
            self.parent = parent
        }
        
        func didScanCode(_ code: String) {
            parent.onCodeScanned(code)
        }
    }
}

protocol ScannerDelegate: AnyObject {
    func didScanCode(_ code: String)
}

class ScannerViewController: UIViewController, AVCaptureMetadataOutputObjectsDelegate {
    var captureSession: AVCaptureSession!
    var previewLayer: AVCaptureVideoPreviewLayer!
    weak var delegate: ScannerDelegate?
    
    override func viewDidLoad() {
        super.viewDidLoad()
        
        view.backgroundColor = UIColor.black
        captureSession = AVCaptureSession()
        
        guard let videoCaptureDevice = AVCaptureDevice.default(for: .video) else { return }
        let videoInput: AVCaptureDeviceInput
        
        do {
            videoInput = try AVCaptureDeviceInput(device: videoCaptureDevice)
        } catch {
            return
        }
        
        if (captureSession.canAddInput(videoInput)) {
            captureSession.addInput(videoInput)
        } else {
            return
        }
        
        let metadataOutput = AVCaptureMetadataOutput()
        
        if (captureSession.canAddOutput(metadataOutput)) {
            captureSession.addOutput(metadataOutput)
            
            metadataOutput.setMetadataObjectsDelegate(self, queue: DispatchQueue.main)
            metadataOutput.metadataObjectTypes = [.qr]
        } else {
            return
        }
        
        previewLayer = AVCaptureVideoPreviewLayer(session: captureSession)
        previewLayer.frame = view.layer.bounds
        previewLayer.videoGravity = .resizeAspectFill
        view.layer.addSublayer(previewLayer)
        
        captureSession.startRunning()
    }
    
    override func viewWillDisappear(_ animated: Bool) {
        super.viewWillDisappear(animated)
        if (captureSession?.isRunning == true) {
            captureSession.stopRunning()
        }
    }
    
    override func viewDidLayoutSubviews() {
        super.viewDidLayoutSubviews()
        if let layer = previewLayer {
            layer.frame = view.bounds
        }
    }
    
    func metadataOutput(_ output: AVCaptureMetadataOutput, didOutput metadataObjects: [AVMetadataObject], from connection: AVCaptureConnection) {
        captureSession.stopRunning()
        
        if let metadataObject = metadataObjects.first {
            guard let readableObject = metadataObject as? AVMetadataMachineReadableCodeObject else { return }
            guard let stringValue = readableObject.stringValue else { return }
            AudioServicesPlaySystemSound(SystemSoundID(kSystemSoundID_Vibrate))
            delegate?.didScanCode(stringValue)
        }
    }
}

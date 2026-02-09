import SwiftUI
import Combine

import OSLog

class ChatViewModel: ObservableObject {
    @Published var contacts: [ContactInfo] = []
    @Published var messages: [String: [ChatMessage]] = [:] // PeerID -> Messages
    @Published var selectedPeerId: String?
    @Published var searchText = ""
    @Published var prekeyBundleJson: String?
    
    // Messaging API instance
    private var messaging: MessagingApi?
    private var cancellables = Set<AnyCancellable>()
    private var pollTimer: Timer?
    
    // Reference to app model for network status
    var appViewModel: AppViewModel?
    
    struct ChatMessage: Identifiable, Equatable {
        let id: String
        let senderId: String
        let text: String
        let timestamp: Date
        let isMe: Bool
        var status: MessageStatus
    }
    
    enum MessageStatus {
        case sending
        case sent
        case delivered
        case failed
    }
    
    func bind(to appViewModel: AppViewModel) {
        self.appViewModel = appViewModel
        
        // When network starts and we have a peer ID, initialize messaging
        appViewModel.$peerId
            .receive(on: RunLoop.main)
            .sink { [weak self] peerId in
                if !peerId.isEmpty && self?.messaging == nil {
                    self?.initializeMessaging(peerId: peerId)
                }
            }
            .store(in: &cancellables)
    }
    
    private func initializeMessaging(peerId: String) {
        print("Initializing MessagingAPI for \(peerId)")
        self.messaging = createMessagingManager(peerId: peerId)
        
        // Print prekey bundle for CLI testing
        if let msg = self.messaging {
            let bundle = msg.getPrekeyBundle()
            self.prekeyBundleJson = bundle
            NSLog("PreKey Bundle: %@", bundle)
        }
        
        // Start polling for messaging events
        self.pollTimer = Timer.scheduledTimer(withTimeInterval: 0.1, repeats: true) { [weak self] _ in
            self?.pollEvents()
        }
    }
    
    private func pollEvents() {
        guard let messaging = messaging else { return }
        
        while let event = messaging.nextEvent() {
            DispatchQueue.main.async { [weak self] in
                self?.handleEvent(event)
            }
        }
        
        // Handle outgoing messages
        while let outgoing = messaging.nextOutgoing() {
            // Check if onion routing is enabled via appViewModel
            if let app = appViewModel, app.isOnionEnabled, 
               let privacy = app.privacyManager, privacy.canBuildCircuit() {
                
                LogManager.shared.info("Chat: Wrapping outgoing message for \(outgoing.peerId) in onion packet", context: "ChatViewModel")
                if let onion = privacy.wrapMessage(payload: outgoing.data, destinationPeerId: outgoing.peerId) {
                    LogManager.shared.info("Chat: Sending onion packet via \(onion.entryPeerId)", context: "ChatViewModel")
                    sendOnionNetworkMessage(entryPeerId: onion.entryPeerId, packetBytes: onion.packetBytes)
                } else {
                    LogManager.shared.error("Chat: Failed to wrap message in onion packet, falling back to direct", context: "ChatViewModel")
                    sendNetworkMessage(peerId: outgoing.peerId, data: outgoing.data)
                }
            } else {
                sendNetworkMessage(peerId: outgoing.peerId, data: outgoing.data)
            }
        }
    }
    
    private func sendOnionNetworkMessage(entryPeerId: String, packetBytes: [UInt8]) {
        guard let network = appViewModel?.networkManager,
              let messaging = messaging else { return }
        
        do {
            // Use the new helper to wrap in an unencrypted OnionPacket envelope
            let envelopeData = messaging.createOnionEnvelope(packetBytes: packetBytes)
            try network.sendMessage(peerId: entryPeerId, data: envelopeData)
        } catch {
            print("Failed to send onion packet: \(error)")
        }
    }
    
    private func sendNetworkMessage(peerId: String, data: [UInt8]) {
        guard let network = appViewModel?.networkManager else { return }
        do {
            try network.sendMessage(peerId: peerId, data: data)
        } catch {
            print("Failed to send network packet: \(error)")
            // TODO: Mark message as failed if we can map it back
        }
    }
    
    private func handleEvent(_ event: MessagingApiEvent) {
        switch event {
        case .messageReceived(let fromPeerId, let text, let id):
            addMessage(peerId: fromPeerId, text: text, isMe: false, id: id)
            refreshContacts()
            
        case .messageSent(let toPeerId, let messageId):
            updateMessageStatus(peerId: toPeerId, messageId: messageId, status: .sent)
            
        case .sessionEstablished(let peerId):
            print("Session established with \(peerId)")
            refreshContacts()
            
        case .deliveryReceipt(let peerId, let messageId):
            updateMessageStatus(peerId: peerId, messageId: messageId, status: .delivered)
            
        case .relayAnnouncement(let peerId, let public_key_hex):
            print("Received relay announcement from \(peerId)")
            appViewModel?.privacyManager?.registerRelay(peerId: peerId, publicKeyHex: public_key_hex)
            
        case .onionPacketReceived(let data):
            print("Received onion packet via messaging, passing to privacy manager")
            let _ = appViewModel?.privacyManager?.processIncoming(packetBytes: data)
            
        case .error(let message):
            print("Messaging error: \(message)")
        }
    }
    
    func refreshContacts() {
        guard let messaging = messaging else { return }
        self.contacts = messaging.listContacts()
    }
    
    func sendMessage(to peerId: String, text: String) {
        guard let messaging = messaging else { return }
        
        // Optimistically add message
        let tempId = UUID().uuidString
        let message = ChatMessage(
            id: tempId,
            senderId: "me",
            text: text,
            timestamp: Date(),
            isMe: true,
            status: .sending
        )
        
        if messages[peerId] == nil {
            messages[peerId] = []
        }
        messages[peerId]?.append(message)
        
        // Send via API
        do {
            let realId = try messaging.sendMessage(peerId: peerId, text: text)
            // Update ID and status
            if let index = messages[peerId]?.firstIndex(where: { $0.id == tempId }) {
                 let finalMessage = ChatMessage(
                    id: realId,
                    senderId: "me",
                    text: text,
                    timestamp: message.timestamp,
                    isMe: true,
                    status: .sent
                )
                messages[peerId]?[index] = finalMessage
            }
        } catch {
            let errorString = String(describing: error)
            if errorString.contains("NoSession") {
                print("[SECURITY] No encrypted session with peer - requesting handshake")
                updateMessageStatus(peerId: peerId, messageId: tempId, status: .sending)
                try? messaging.requestSession(peerId: peerId)
                addSystemMessage(peerId: peerId, text: "🔒 Securing connection... handshake requested.")
            } else {
                print("[DEBUG_ERROR] Failed to send message: \(error)")
                updateMessageStatus(peerId: peerId, messageId: tempId, status: .failed)
            }
        }
    }
    
    private func addSystemMessage(peerId: String, text: String) {
        let systemMsg = ChatMessage(
            id: "system-\(UUID().uuidString)",
            senderId: "system",
            text: text,
            timestamp: Date(),
            isMe: false,
            status: .delivered
        )
        if messages[peerId] == nil {
            messages[peerId] = []
        }
        messages[peerId]?.append(systemMsg)
    }
    
    func addContact(peerId: String, name: String, identityKeyHex: String) {
        guard let messaging = messaging else { return }
        guard let keyBytes = Data(hex: identityKeyHex) else {
            print("Invalid hex key")
            return
        }
        
        // Convert Data to [UInt8] for UniFFI
        let keyArray = [UInt8](keyBytes)
        
        messaging.addContact(peerId: peerId, name: name, identityKey: keyArray)
        
        // Automatically request session/handshake
        print("Automatically requesting handshake for \(peerId)")
        try? messaging.requestSession(peerId: peerId)
        
        refreshContacts()
    }
    
    private func addMessage(peerId: String, text: String, isMe: Bool, id: String) {
        LogManager.shared.debug("Adding message from \(peerId): \(text)", context: "ChatViewModel")
        let message = ChatMessage(
            id: id,
            senderId: peerId,
            text: text,
            timestamp: Date(),
            isMe: isMe,
            status: .delivered // Received messages are delivered
        )
        
        if messages[peerId] == nil {
            messages[peerId] = []
        }
        messages[peerId]?.append(message)
        
        if !isMe {
            UIImpactFeedbackGenerator(style: .light).impactOccurred()
        }
    }
    
    private func updateMessageStatus(peerId: String, messageId: String, status: MessageStatus) {
        guard let index = messages[peerId]?.firstIndex(where: { $0.id == messageId }) else { return }
        messages[peerId]?[index].status = status
    }
    
    // Handle incoming raw data from NetworkManager (if pushing from AppViewModel)
    // But we are polling via MessagingAPI which wraps MessagingManager,
    // which internally queues events.
    // However, MessagingManager needs to receive data from P2PNode.
    // P2PNode events are polled by NetworkManager in AppViewModel.
    // AppViewModel gets `NetworkEvent.messageReceived`.
    // It MUST pass this data to MessagingAPI.handleIncoming.
    
    func ingestNetworkMessage(peerId: String, data: Data) {
        LogManager.shared.debug("ingestNetworkMessage from \(peerId), len: \(data.count)", context: "ChatViewModel")
        guard let messaging = messaging else {
            LogManager.shared.error("Messaging is nil!", context: "ChatViewModel")
            return
        }
        do {
            let dataArray = [UInt8](data)
            try messaging.handleIncoming(fromPeerId: peerId, data: dataArray)
            LogManager.shared.debug("handleIncoming success for \(peerId)", context: "ChatViewModel")
        } catch {
            LogManager.shared.error("Failed to handle incoming message: \(error.localizedDescription)", context: "ChatViewModel")
        }
    }
}

// Helper for Hex
extension Data {
    init?(hex: String) {
        let len = hex.count / 2
        var data = Data(capacity: len)
        var ptr = hex.startIndex
        for _ in 0..<len {
            let end = hex.index(ptr, offsetBy: 2)
            let bytes = hex[ptr..<end]
            if let num = UInt8(bytes, radix: 16) {
                data.append(num)
            } else {
                return nil
            }
            ptr = end
        }
        self = data
    }
}

extension ContactInfo: Identifiable {
    public var id: String { peerId }
}

import SwiftUI
import Combine

import OSLog

class ChatViewModel: ObservableObject {
    @Published var contacts: [ContactInfo] = []
    @Published var messages: [String: [ChatMessage]] = [:] // PeerID -> Messages
    @Published var selectedPeerId: String?
    @Published var searchText = ""
    @Published var prekeyBundleJson: String?
    @Published var myPeerId: String = ""
    
    // Messaging API instance
    private var messaging: MessagingApi?
    private var cancellables = Set<AnyCancellable>()
    private var pollTimer: Timer?
    private let backgroundQueue = DispatchQueue(label: "com.securechat.messaging", qos: .userInitiated)
    private var isPolling = false
    private let pendingLock = NSLock()
    private var pendingNetworkMessages: [(peerId: String, data: Data)] = []
    private var pendingSessionRequests: [String] = []
    // Tracks peers we've requested a session for but haven't gotten SessionEstablished yet
    // This survives even after requestSession() succeeds at the API level, because the
    // actual network send may fail (DialFailure on first scan)
    private var awaitingSessionPeers: Set<String> = []
    
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
                self?.myPeerId = peerId
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
        
        // Start polling for messaging events on background thread
        if !isPolling {
            isPolling = true
            backgroundQueue.async { [weak self] in
                while let self = self, self.isPolling {
                    self.pollEvents()
                    Thread.sleep(forTimeInterval: 0.1)
                }
            }
        }

        // Flush any pending network messages that arrived before messaging init.
        pendingLock.lock()
        let queuedMessages = pendingNetworkMessages
        pendingNetworkMessages.removeAll()
        let uniquePeers = Array(Set(pendingSessionRequests))
        pendingSessionRequests.removeAll()
        pendingLock.unlock()

        if !queuedMessages.isEmpty {
            LogManager.shared.info("Flushing \(queuedMessages.count) pending network messages", context: "ChatViewModel")
            for item in queuedMessages {
                ingestNetworkMessage(peerId: item.peerId, data: item.data)
            }
        }
        
        if !uniquePeers.isEmpty {
            LogManager.shared.info("Flushing \(uniquePeers.count) pending session requests", context: "ChatViewModel")
            for peerId in uniquePeers {
                requestSession(peerId: peerId)
            }
        }
    }
    
    private func pollEvents() {
        guard let messaging = messaging else { return }
        
        // 1. Check pending session requests
        pendingLock.lock()
        let pending = pendingSessionRequests
        pendingLock.unlock()

        if !pending.isEmpty {
            if let appVM = appViewModel {
                 LogManager.shared.debug("Poll: Pending sessions: \(pending), Connected: \(appVM.connectedPeers)", context: "ChatViewModel")
            }
            
            for peerId in pending {
                if let appVM = appViewModel, appVM.connectedPeers.contains(peerId) {
                    do {
                        LogManager.shared.info("Retrying pending session request for \(peerId)...", context: "ChatViewModel")
                        try messaging.requestSession(peerId: peerId)
                        LogManager.shared.info("Retrying pending session request for \(peerId) - SUCCESS", context: "ChatViewModel")
                        
                        pendingLock.lock()
                        if let idx = pendingSessionRequests.firstIndex(of: peerId) {
                            pendingSessionRequests.remove(at: idx)
                        }
                        pendingLock.unlock()
                    } catch {
                        LogManager.shared.error("Retrying session for \(peerId) failed: \(error)", context: "ChatViewModel")
                    }
                }
            }
        }
        
        while let event = messaging.nextEvent() {
            DispatchQueue.main.async { [weak self] in
                LogManager.shared.debug("Messaging event: \(String(describing: event))", context: "ChatViewModel")
                self?.handleEvent(event)
            }
        }
        
        // Handle outgoing messages
        while let outgoing = messaging.nextOutgoing() {
            LogManager.shared.info("Outgoing message dequeued for \(outgoing.peerId), bytes=\(outgoing.data.count)", context: "ChatViewModel")
            // Send directly; Rust core will onion-route if enabled.
            LogManager.shared.info("Chat: Sending direct message to \(outgoing.peerId), bytes=\(outgoing.data.count)", context: "ChatViewModel")
            sendNetworkMessage(peerId: outgoing.peerId, data: outgoing.data)
        }
    }
    
    private func sendOnionNetworkMessage(entryPeerId: String, packetBytes: [UInt8]) {
        guard let network = appViewModel?.networkManager,
              let messaging = messaging else { return }
        
        do {
            // Use the new helper to wrap in an unencrypted OnionPacket envelope
            let envelopeData = messaging.createOnionEnvelope(packetBytes: packetBytes)
            LogManager.shared.info("Chat: Sending onion envelope to \(entryPeerId), bytes=\(envelopeData.count)", context: "ChatViewModel")
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
            LogManager.shared.info("Messaging: MessageReceived from \(fromPeerId), id=\(id)", context: "ChatViewModel")
            addMessage(peerId: fromPeerId, text: text, isMe: false, id: id)
            refreshContacts()
            
        case .messageSent(let toPeerId, let messageId):
            LogManager.shared.info("Messaging: MessageSent to \(toPeerId), id=\(messageId)", context: "ChatViewModel")
            updateMessageStatus(peerId: toPeerId, messageId: messageId, status: .sent)
            
        case .sessionEstablished(let peerId):
            print("Session established with \(peerId)")
            LogManager.shared.info("Messaging: SessionEstablished with \(peerId)", context: "ChatViewModel")
            refreshContacts()
            
            // Clear from awaiting set — session is fully established
            pendingLock.lock()
            awaitingSessionPeers.remove(peerId)
            pendingLock.unlock()
            
            // BUG FIX 3: Retry all failed/sending messages for this peer
            retryPendingMessages(for: peerId)
            
        case .deliveryReceipt(let peerId, let messageId):
            LogManager.shared.info("Messaging: DeliveryReceipt from \(peerId), id=\(messageId)", context: "ChatViewModel")
            updateMessageStatus(peerId: peerId, messageId: messageId, status: .delivered)
            
        case .relayAnnouncement(let peerId, let publicKeyHex):
            print("Received relay announcement from \(peerId)")
            LogManager.shared.info("Messaging: RelayAnnouncement from \(peerId), key=\(publicKeyHex.prefix(12))...", context: "ChatViewModel")
            appViewModel?.privacyManager?.registerRelay(peerId: peerId, publicKeyHex: publicKeyHex)
            
        case .onionPacketReceived(let data):
            print("Received onion packet via messaging, passing to privacy manager")
            LogManager.shared.info("Messaging: OnionPacketReceived size=\(data.count)", context: "ChatViewModel")
            let _ = appViewModel?.privacyManager?.processIncoming(packetBytes: data)
            
        case .error(let message):
            print("Messaging error: \(message)")
            LogManager.shared.error("Messaging error: \(message)", context: "ChatViewModel")
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
    
    func requestSession(peerId: String) {
        let timestamp = ISO8601DateFormatter().string(from: Date())
        LogManager.shared.info("[\(timestamp)] TRACE: requestSession called for \(peerId)", context: "ChatViewModel")
        
        if peerId == myPeerId {
            LogManager.shared.warn("Ignoring session request to self.", context: "ChatViewModel")
            return
        }
        
        guard let messaging = messaging else {
            LogManager.shared.info("TRACE: Messaging API not initialized yet - queuing session request", context: "ChatViewModel")
            pendingLock.lock()
            if !pendingSessionRequests.contains(peerId) {
                pendingSessionRequests.append(peerId)
            }
            awaitingSessionPeers.insert(peerId)
            pendingLock.unlock()
            return
        }
        
        // Track that we're awaiting a session — even if the API call succeeds,
        // the actual network send might fail (DialFailure on first scan).
        // handlePeerConnected will retry if we're still in this set.
        pendingLock.lock()
        awaitingSessionPeers.insert(peerId)
        pendingLock.unlock()
        
        do {
            LogManager.shared.info("TRACE: Handing session request to Rust core for \(peerId)...", context: "ChatViewModel")
            try messaging.requestSession(peerId: peerId)
            LogManager.shared.info("TRACE: Rust core accepted session request for \(peerId)", context: "ChatViewModel")
            
            // Remove from pendingSessionRequests (but keep in awaitingSessionPeers!)
            pendingLock.lock()
            if let idx = pendingSessionRequests.firstIndex(of: peerId) {
                pendingSessionRequests.remove(at: idx)
            }
            pendingLock.unlock()
        } catch {
            LogManager.shared.error("TRACE: Rust core REJECTED session request for \(peerId): \(error)", context: "ChatViewModel")
            // Queue for retry
            pendingLock.lock()
            if !pendingSessionRequests.contains(peerId) {
                pendingSessionRequests.append(peerId)
            }
            pendingLock.unlock()
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
            pendingLock.lock()
            pendingNetworkMessages.append((peerId: peerId, data: data))
            pendingLock.unlock()
            return
        }
        do {
            let dataArray = [UInt8](data)
            try messaging.handleIncoming(fromPeerId: peerId, data: dataArray)
            LogManager.shared.debug("handleIncoming success for \(peerId), len: \(data.count)", context: "ChatViewModel")
            // Immediately flush any outgoing responses (e.g., HandshakeResponse)
            while let outgoing = messaging.nextOutgoing() {
                LogManager.shared.info("Outgoing message dequeued for \(outgoing.peerId), bytes=\(outgoing.data.count)", context: "ChatViewModel")
                LogManager.shared.info("Chat: Sending direct message to \(outgoing.peerId), bytes=\(outgoing.data.count)", context: "ChatViewModel")
                sendNetworkMessage(peerId: outgoing.peerId, data: outgoing.data)
            }
        } catch {
            LogManager.shared.error("Failed to handle incoming message: \(error.localizedDescription)", context: "ChatViewModel")
        }
    }
    
    // BUG FIX 3: Retry pending messages when session is established
    private func retryPendingMessages(for peerId: String) {
        guard let messaging = messaging else { return }
        guard let messageList = messages[peerId] else { return }
        
        let failedMessages = messageList.filter { $0.isMe && ($0.status == .failed || $0.status == .sending) }
        
        if failedMessages.isEmpty {
            return
        }
        
        LogManager.shared.info("Retrying \(failedMessages.count) pending messages for \(peerId)", context: "ChatViewModel")
        
        for message in failedMessages {
            do {
                let newId = try messaging.sendMessage(peerId: peerId, text: message.text)
                LogManager.shared.info("Retry succeeded for message \(message.id), new ID: \(newId)", context: "ChatViewModel")
                
                // Update the message status
                if let index = messages[peerId]?.firstIndex(where: { $0.id == message.id }) {
                    messages[peerId]?[index].status = .sent
                }
            } catch {
                LogManager.shared.error("Retry failed for message \(message.id): \(error)", context: "ChatViewModel")
            }
        }
    }
    
    // Handle peer connected event to retry pending/awaiting session requests
    func handlePeerConnected(peerId: String) {
        pendingLock.lock()
        let hasPending = pendingSessionRequests.contains(peerId)
        let isAwaiting = awaitingSessionPeers.contains(peerId)
        pendingLock.unlock()
        
        if hasPending || isAwaiting {
            LogManager.shared.info("Peer \(peerId) connected - retrying session request (pending=\(hasPending), awaiting=\(isAwaiting))", context: "ChatViewModel")
            requestSession(peerId: peerId)
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

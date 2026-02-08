import SwiftUI
import Combine

class ChatViewModel: ObservableObject {
    @Published var contacts: [ContactInfo] = []
    @Published var messages: [String: [ChatMessage]] = [:] // PeerID -> Messages
    @Published var selectedPeerId: String?
    @Published var searchText = ""
    
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
    
    struct ContactInfo: Identifiable, Equatable {
        let id: String
        let peerId: String
        let name: String
        let sessionEstablished: Bool
        
        init(peerId: String, name: String, sessionEstablished: Bool) {
            self.id = peerId
            self.peerId = peerId
            self.name = name
            self.sessionEstablished = sessionEstablished
        }
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
            sendNetworkMessage(peerId: outgoing.peerId, data: outgoing.data)
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
            
        case .messageSent(let toPeerId, let messageId):
            updateMessageStatus(peerId: toPeerId, messageId: messageId, status: .sent)
            
        case .sessionEstablished(let peerId):
            print("Session established with \(peerId)")
            // Refresh contact status if needed
            
        case .deliveryReceipt(let peerId, let messageId):
            updateMessageStatus(peerId: peerId, messageId: messageId, status: .delivered)
            
        case .error(let message):
            print("Messaging error: \(message)")
        }
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
                var updated = messages[peerId]![index]
                // Create new message with real ID
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
            print("[DEBUG_ERROR] Failed to send message: \(error)")
            updateMessageStatus(peerId: peerId, messageId: tempId, status: .failed)
        }
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
        
        let info = ContactInfo(peerId: peerId, name: name, sessionEstablished: false)
        contacts.append(info)
    }
    
    private func addMessage(peerId: String, text: String, isMe: Bool, id: String) {
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
        guard let messaging = messaging else { return }
        do {
            let dataArray = [UInt8](data)
            try messaging.handleIncoming(fromPeerId: peerId, data: dataArray)
        } catch {
            print("Failed to handle incoming message: \(error)")
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

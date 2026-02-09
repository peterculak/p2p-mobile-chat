import SwiftUI

struct ChatView: View {
    @ObservedObject var viewModel: ChatViewModel
    @State private var showingAddContact = false
    @State private var newContactId = ""
    @State private var newContactName = ""
    @State private var newContactKey = ""
    
    var body: some View {
        NavigationView {
            ZStack {
                Color.bgPrimary.ignoresSafeArea()
                
                if viewModel.contacts.isEmpty {
                    EmptyStateView(showingAddContact: $showingAddContact)
                } else {
                    List {
                        ForEach(viewModel.contacts, id: \.peerId) { contact in
                            NavigationLink(destination: ChatDetailView(viewModel: viewModel, peerId: contact.peerId)) {
                                ContactRow(contact: contact)
                            }
                            .listRowBackground(Color.bgSecondary)
                            .listRowSeparatorTint(Color.white.opacity(0.1))
                        }
                    }
                    .listStyle(.plain)
                    .background(Color.bgPrimary)
                }
            }
            .navigationTitle("Messages")
            .toolbar {
                ToolbarItem(placement: .navigationBarTrailing) {
                    Button(action: { showingAddContact = true }) {
                        Image(systemName: "plus.circle.fill")
                            .font(.title2)
                            .foregroundStyle(LinearGradient.accent)
                    }
                }
            }
            .sheet(isPresented: $showingAddContact) {
                AddContactView(
                    isPresented: $showingAddContact,
                    peerId: $newContactId,
                    name: $newContactName,
                    key: $newContactKey,
                    onAdd: {
                        viewModel.addContact(peerId: newContactId, name: newContactName, identityKeyHex: newContactKey)
                    }
                )
            }
        }
    }
}

struct EmptyStateView: View {
    @Binding var showingAddContact: Bool
    
    var body: some View {
        VStack(spacing: 20) {
            Image(systemName: "bubble.left.and.bubble.right.fill")
                .font(.system(size: 60))
                .foregroundStyle(LinearGradient.accent)
                .padding()
                .background(
                    Circle()
                        .fill(Color.bgSecondary)
                        .frame(width: 120, height: 120)
                )
            
            Text("No Chats Yet")
                .font(.title2.bold())
                .foregroundColor(.white)
            
            Text("Add a contact to start messaging securely.")
                .font(.subheadline)
                .foregroundColor(.white.opacity(0.6))
                .multilineTextAlignment(.center)
                .padding(.horizontal)
            
            Button(action: { showingAddContact = true }) {
                Text("Add Contact")
                    .fontWeight(.semibold)
                    .foregroundColor(.white)
                    .padding(.horizontal, 24)
                    .padding(.vertical, 12)
                    .background(LinearGradient.accent)
                    .clipShape(Capsule())
            }
            .padding(.top, 10)
        }
    }
}

struct ContactRow: View {
    let contact: ContactInfo 
    // ContactInfo is from generated code
    
    var body: some View {
        HStack(spacing: 16) {
            ZStack {
                Circle()
                    .fill(Color.accentStart.opacity(0.2))
                    .frame(width: 48, height: 48)
                
                Text(String(contact.name.prefix(1)))
                    .font(.headline)
                    .foregroundColor(.accentEnd)
            }
            
            VStack(alignment: .leading, spacing: 4) {
                Text(contact.name)
                    .font(.headline)
                    .foregroundColor(.white)
                
                Text(String(contact.peerId.prefix(8)) + "...")
                    .font(.caption)
                    .foregroundColor(.white.opacity(0.5))
            }
            
            Spacer()
            
            if contact.sessionEstablished {
                Image(systemName: "lock.fill")
                    .font(.caption)
                    .foregroundColor(.green)
            }
        }
        .padding(.vertical, 8)
    }
}

struct AddContactView: View {
    @Binding var isPresented: Bool
    @Binding var peerId: String
    @Binding var name: String
    @Binding var key: String
    var onAdd: () -> Void
    
    var body: some View {
        NavigationView {
            Form {
                Section(header: Text("Contact Info")) {
                    TextField("Name", text: $name)
                    TextField("Peer ID", text: $peerId)
                        .autocapitalization(.none)
                        .disableAutocorrection(true)
                    TextField("Identity Key (Hex)", text: $key)
                        .autocapitalization(.none)
                        .disableAutocorrection(true)
                }
            }
            .navigationTitle("Add Contact")
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { isPresented = false }
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Add") {
                        onAdd()
                        isPresented = false
                    }
                    .disabled(peerId.isEmpty || name.isEmpty || key.isEmpty)
                }
            }
        }
    }
}

struct ChatDetailView: View {
    @ObservedObject var viewModel: ChatViewModel
    let peerId: String
    @State private var messageText = ""
    
    var body: some View {
        VStack(spacing: 0) {
            ScrollViewReader { proxy in
                ScrollView {
                    LazyVStack(spacing: 12) {
                        ForEach(viewModel.messages[peerId] ?? []) { message in
                            MessageBubble(message: message)
                                .id(message.id)
                        }
                    }
                    .padding()
                }
                .onChange(of: viewModel.messages[peerId]) { _ in
                    if let last = viewModel.messages[peerId]?.last {
                        withAnimation {
                            proxy.scrollTo(last.id, anchor: .bottom)
                        }
                    }
                }
            }
            .background(Color.bgPrimary)
            
            // Input area
            HStack(spacing: 12) {
                TextField("Message...", text: $messageText)
                    .padding(10)
                    .background(Color.bgSecondary)
                    .cornerRadius(20)
                    .foregroundColor(.white)
                
                Button(action: sendMessage) {
                    Image(systemName: "paperplane.fill")
                        .font(.title2)
                        .foregroundStyle(messageText.isEmpty ? LinearGradient(colors: [.gray], startPoint: .top, endPoint: .bottom) : LinearGradient.accent)
                        .rotationEffect(.degrees(45))
                }
                .disabled(messageText.isEmpty)
            }
            .padding()
            .background(.ultraThinMaterial)
        }
        .navigationTitle("Chat") // In real app, name
        .navigationBarTitleDisplayMode(.inline)
    }
    
    func sendMessage() {
        guard !messageText.isEmpty else { return }
        viewModel.sendMessage(to: peerId, text: messageText)
        messageText = ""
        UIImpactFeedbackGenerator(style: .light).impactOccurred()
    }
}

struct MessageBubble: View {
    let message: ChatViewModel.ChatMessage
    
    var body: some View {
        HStack {
            if message.isMe { Spacer() }
            
            VStack(alignment: message.isMe ? .trailing : .leading, spacing: 4) {
                Text(message.text)
                    .padding(.horizontal, 16)
                    .padding(.vertical, 10)
                    .background(
                        message.isMe ?
                        LinearGradient.accent :
                        LinearGradient(colors: [.bgSecondary], startPoint: .top, endPoint: .bottom)
                    )
                    .foregroundColor(.white)
                    .clipShape(RoundedRectangle(cornerRadius: 16, style: .continuous))
                
                if message.isMe {
                    StatusIcon(status: message.status)
                }
            }
            
            if !message.isMe { Spacer() }
        }
    }
}

struct StatusIcon: View {
    let status: ChatViewModel.MessageStatus
    
    var body: some View {
        switch status {
        case .sending:
            Image(systemName: "circle")
                .font(.caption2)
                .foregroundColor(.white.opacity(0.5))
        case .sent:
            Image(systemName: "checkmark")
                .font(.caption2)
                .foregroundColor(.white.opacity(0.5))
        case .delivered:
            Image(systemName: "checkmark.circle.fill")
                .font(.caption2)
                .foregroundColor(.white.opacity(0.8))
        case .failed:
            Image(systemName: "exclamationmark.circle.fill")
                .font(.caption2)
                .foregroundColor(.red)
        }
    }
}

struct ChatView_Previews: PreviewProvider {
    static var previews: some View {
        ChatView(viewModel: ChatViewModel())
    }
}

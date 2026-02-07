import SwiftUI

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

// MARK: - Identity View Model
class IdentityViewModel: ObservableObject {
    @Published var identity: Identity?
    @Published var fingerprint: String = ""
    @Published var isGenerating: Bool = false
    
    func generateNewIdentity() {
        isGenerating = true
        
        // Add slight delay for animation effect
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.3) { [weak self] in
            let newIdentity = generateIdentity()
            self?.identity = newIdentity
            self?.fingerprint = getPublicKeyFingerprint(identity: newIdentity)
            self?.isGenerating = false
        }
    }
}

// MARK: - Content View
struct ContentView: View {
    @StateObject private var viewModel = IdentityViewModel()
    @State private var showCopied = false
    
    var body: some View {
        ZStack {
            // Background gradient
            LinearGradient(
                colors: [.bgPrimary, Color(red: 0.08, green: 0.08, blue: 0.15)],
                startPoint: .top,
                endPoint: .bottom
            )
            .ignoresSafeArea()
            
            // Ambient glow effect
            Circle()
                .fill(LinearGradient.accent)
                .blur(radius: 100)
                .opacity(0.3)
                .offset(y: -200)
                .ignoresSafeArea()
            
            VStack(spacing: 32) {
                Spacer()
                
                // App icon/logo
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
                .padding(.bottom, 8)
                
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
                    .transition(.asymmetric(
                        insertion: .scale(scale: 0.9).combined(with: .opacity),
                        removal: .opacity
                    ))
                }
                
                Spacer()
                
                // Generate button
                Button(action: {
                    withAnimation(.spring(response: 0.4, dampingFraction: 0.7)) {
                        viewModel.generateNewIdentity()
                    }
                    // Haptic feedback
                    let generator = UIImpactFeedbackGenerator(style: .medium)
                    generator.impactOccurred()
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
                    .background(
                        LinearGradient.accent
                            .opacity(viewModel.isGenerating ? 0.7 : 1.0)
                    )
                    .clipShape(RoundedRectangle(cornerRadius: 16, style: .continuous))
                    .shadow(color: .accentStart.opacity(0.5), radius: 20, y: 10)
                }
                .disabled(viewModel.isGenerating)
                .padding(.horizontal, 32)
                .padding(.bottom, 40)
            }
        }
        .overlay(
            // Copied toast
            VStack {
                if showCopied {
                    Text("✓ Copied to clipboard")
                        .font(.subheadline.weight(.medium))
                        .foregroundColor(.white)
                        .padding(.horizontal, 20)
                        .padding(.vertical, 12)
                        .background(.ultraThinMaterial)
                        .clipShape(Capsule())
                        .transition(.move(edge: .top).combined(with: .opacity))
                        .onAppear {
                            DispatchQueue.main.asyncAfter(deadline: .now() + 2) {
                                withAnimation {
                                    showCopied = false
                                }
                            }
                        }
                }
                Spacer()
            }
            .padding(.top, 60)
        )
    }
}

// MARK: - Identity Card
struct IdentityCard: View {
    let fingerprint: String
    let publicKeyHex: String
    @Binding var showCopied: Bool
    
    var body: some View {
        VStack(spacing: 20) {
            // Fingerprint section
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
            
            // Public key section
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
            
            // Copy button
            Button(action: {
                UIPasteboard.general.string = publicKeyHex
                withAnimation(.spring(response: 0.3, dampingFraction: 0.7)) {
                    showCopied = true
                }
                let generator = UINotificationFeedbackGenerator()
                generator.notificationOccurred(.success)
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

// MARK: - Preview
#Preview {
    ContentView()
}

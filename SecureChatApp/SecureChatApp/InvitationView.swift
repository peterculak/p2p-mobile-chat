import SwiftUI
import CoreImage.CIFilterBuiltins

struct InvitationView: View {
    let peerId: String
    let addresses: [String]
    
    var connectionString: String {
        // Format: securechat://invite/PEER_ID/MULTIADDR_BASE64
        // For now, let's just use the first valid public address or local one
        if let addr = addresses.first(where: { !$0.contains("127.0.0.1") }) ?? addresses.first {
             return "securechat://invite/\(peerId)/\(addr)"
        }
        return "securechat://invite/\(peerId)/unknown"
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
            
            ZStack {
                RoundedRectangle(cornerRadius: 20)
                    .fill(Color.white)
                    .frame(width: 250, height: 250)
                
                if let qrImage = generateQRCode(from: connectionString) {
                    Image(uiImage: qrImage)
                        .interpolation(.none)
                        .resizable()
                        .scaledToFit()
                        .frame(width: 230, height: 230)
                } else {
                    Image(systemName: "xmark.circle")
                        .font(.largeTitle)
                        .foregroundColor(.red)
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
        .background(LinearGradient.bgSecondary.ignoresSafeArea())
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

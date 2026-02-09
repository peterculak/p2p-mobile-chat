import SwiftUI
import AVFoundation

struct ScannerView: View {
    @ObservedObject var viewModel: AppViewModel
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
                
                // Trigger dial
                DispatchQueue.main.async {
                    do {
                        try viewModel.networkManager?.dial(address: address)
                        let generator = UINotificationFeedbackGenerator()
                        generator.notificationOccurred(.success)
                        self.presentationMode.wrappedValue.dismiss()
                    } catch {
                        LogManager.shared.error("Failed to dial scanned address: \(error)", context: "ScannerView")
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

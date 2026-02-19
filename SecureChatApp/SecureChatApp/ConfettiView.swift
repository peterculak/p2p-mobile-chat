import SwiftUI
import UIKit

struct ConfettiView: View {
    @Binding var counter: Int
    
    var body: some View {
        ConfettiUIViewRepresentable(counter: counter)
            .allowsHitTesting(false)
            .ignoresSafeArea()
    }
}

private struct ConfettiUIViewRepresentable: UIViewRepresentable {
    var counter: Int
    
    func makeUIView(context: Context) -> UIView {
        let view = UIView()
        view.backgroundColor = .clear
        return view
    }
    
    func updateUIView(_ uiView: UIView, context: Context) {
        if context.coordinator.lastCounter != counter && counter > 0 {
            context.coordinator.lastCounter = counter
            fireConfetti(in: uiView)
        }
    }
    
    func makeCoordinator() -> Coordinator {
        Coordinator()
    }
    
    class Coordinator {
        var lastCounter = 0
    }
    
    private func fireConfetti(in view: UIView) {
        let emitter = CAEmitterLayer()
        
        // Emit from the top edge spreading across the width
        let width = UIScreen.main.bounds.width
        let height = UIScreen.main.bounds.height
        
        // Start in the top section of the screen (about 1/4 of the way down)
        emitter.emitterPosition = CGPoint(x: width / 2, y: height / 4)
        emitter.emitterShape = .point
        
        // This trick forces the emitter to calculate past particles,
        // instantly placing them on screen in a single explosion burst
        emitter.beginTime = CACurrentMediaTime() - 0.9
        
        let colors: [UIColor] = [
            .systemRed, .systemBlue, .systemGreen, .systemYellow,
            .systemOrange, .systemPurple, .systemPink, .systemTeal
        ]
        
        var cells = [CAEmitterCell]()
        
        for color in colors {
            let cell = CAEmitterCell()
            cell.birthRate = 25 // Quick pop of particles per color (25 * 8 colors = 200 total per second)
            cell.lifetime = 3.0 // Fade out sooner
            cell.lifetimeRange = 1.0
            
            // Speed of shooting outwards
            cell.velocity = 400 // Snappy but not screen-breaking
            cell.velocityRange = 200
            
            // Direction (all directions)
            cell.emissionRange = .pi * 2 // Spread outwards in all 360 degrees
            
            // Spin and size - making particles much smaller
            cell.spin = 3
            cell.spinRange = 4
            cell.scale = 0.3
            cell.scaleRange = 0.2
            
            // Gravity effect pulling back down
            cell.yAcceleration = 800
            
            cell.color = color.cgColor
            
            // Randomly pick rectangle or circle shape
            let isCircle = Bool.random()
            cell.contents = createConfettiImage(isCircle: isCircle).cgImage
            
            cells.append(cell)
        }
        
        emitter.emitterCells = cells
        view.layer.addSublayer(emitter)
        
        // We use a high birthrate to spawn them, but immediately drop it to 0
        // Since beginTime is in the past, the burst has already happened instantly.
        DispatchQueue.main.async {
            emitter.birthRate = 0
        }
        
        // Remove the layer fully after all particles have likely fallen
        DispatchQueue.main.asyncAfter(deadline: .now() + 4.0) {
            emitter.removeFromSuperlayer()
        }
    }
    
    private func createConfettiImage(isCircle: Bool) -> UIImage {
        let size = isCircle ? CGSize(width: 12, height: 12) : CGSize(width: 10, height: 20)
        UIGraphicsBeginImageContextWithOptions(size, false, 0)
        UIColor.white.setFill()
        let rect = CGRect(origin: .zero, size: size)
        
        let path: UIBezierPath
        if isCircle {
            path = UIBezierPath(ovalIn: rect)
        } else {
            // Slightly rounded rectangle
            path = UIBezierPath(roundedRect: rect, cornerRadius: 2.0)
        }
        
        path.fill()
        let image = UIGraphicsGetImageFromCurrentImageContext()
        UIGraphicsEndImageContext()
        return image ?? UIImage()
    }
}

#Preview {
    struct PreviewWrapper: View {
        @State private var count = 0
        var body: some View {
            ZStack {
                Color.black.ignoresSafeArea()
                VStack {
                    Spacer()
                    Button("Fire Confetti") {
                        count += 1
                    }
                    .padding()
                    .background(Color.white)
                    .clipShape(Capsule())
                }
                ConfettiView(counter: $count)
            }
        }
    }
    return PreviewWrapper()
}

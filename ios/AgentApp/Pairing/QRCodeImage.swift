import CoreImage
import CoreImage.CIFilterBuiltins
import SwiftUI

struct QRCodeImage: View {
    let text: String

    var body: some View {
        if let image = makeImage() {
            Image(uiImage: image)
                .interpolation(.none)
                .resizable()
                .scaledToFit()
                .accessibilityLabel("QR code with public WireGuard pairing information")
        } else {
            ContentUnavailableView("Unable to generate QR", systemImage: "qrcode")
        }
    }

    private func makeImage() -> UIImage? {
        let generator = CIFilter.qrCodeGenerator()
        generator.message = Data(text.utf8)
        generator.correctionLevel = "M"
        guard let output = generator.outputImage,
              let cgImage = CIContext().createCGImage(output, from: output.extent) else { return nil }
        return UIImage(cgImage: cgImage)
    }
}

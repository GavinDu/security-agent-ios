import AVFoundation
import SwiftUI

struct QRScannerView: View {
    let onScan: (String) -> Void
    @State private var cameraAllowed = false
    @State private var permissionChecked = false

    var body: some View {
        Group {
            if cameraAllowed {
                ScannerPreview(onScan: onScan)
                    .ignoresSafeArea(edges: .bottom)
            } else {
                ContentUnavailableView(
                    "Camera permission required",
                    systemImage: "camera",
                    description: Text("Allow camera access in Settings to scan your Mac Mini pairing QR.")
                )
            }
        }
        .task {
            let granted = await AVCaptureDevice.requestAccess(for: .video)
            cameraAllowed = granted
            permissionChecked = true
        }
        .navigationTitle("Scan Mac QR")
    }
}

private final class CameraView: UIView {
    override class var layerClass: AnyClass { AVCaptureVideoPreviewLayer.self }
    var previewLayer: AVCaptureVideoPreviewLayer { layer as! AVCaptureVideoPreviewLayer }
}

private struct ScannerPreview: UIViewRepresentable {
    let onScan: (String) -> Void

    func makeCoordinator() -> Coordinator { Coordinator(onScan: onScan) }

    func makeUIView(context: Context) -> CameraView {
        let view = CameraView()
        view.previewLayer.videoGravity = .resizeAspectFill
        context.coordinator.prepare(preview: view.previewLayer)
        return view
    }

    func updateUIView(_ view: CameraView, context: Context) {}

    static func dismantleUIView(_ view: CameraView, coordinator: Coordinator) {
        coordinator.stop()
    }

    final class Coordinator: NSObject, AVCaptureMetadataOutputObjectsDelegate {
        private let session = AVCaptureSession()
        private let queue = DispatchQueue(label: "com.gavindu.agent.qrscanner")
        private let onScan: (String) -> Void
        private var hasScanned = false

        init(onScan: @escaping (String) -> Void) { self.onScan = onScan }

        func prepare(preview: AVCaptureVideoPreviewLayer) {
            preview.session = session
            queue.async {
                guard let device = AVCaptureDevice.default(for: .video),
                      let input = try? AVCaptureDeviceInput(device: device) else { return }
                self.session.beginConfiguration()
                guard self.session.canAddInput(input) else {
                    self.session.commitConfiguration()
                    return
                }
                self.session.addInput(input)
                let metadata = AVCaptureMetadataOutput()
                guard self.session.canAddOutput(metadata) else {
                    self.session.commitConfiguration()
                    return
                }
                self.session.addOutput(metadata)
                metadata.setMetadataObjectsDelegate(self, queue: .main)
                metadata.metadataObjectTypes = [.qr]
                self.session.commitConfiguration()
                self.session.startRunning()
            }
        }

        func stop() { queue.async { if self.session.isRunning { self.session.stopRunning() } } }

        func metadataOutput(_ output: AVCaptureMetadataOutput,
                            didOutput metadataObjects: [AVMetadataObject],
                            from connection: AVCaptureConnection) {
            guard !hasScanned,
                  let code = metadataObjects.compactMap({ $0 as? AVMetadataMachineReadableCodeObject })
                    .first?.stringValue else { return }
            hasScanned = true
            onScan(code)
            stop()
        }
    }
}

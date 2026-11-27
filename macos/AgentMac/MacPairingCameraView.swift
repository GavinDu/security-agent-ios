import AppKit
import AVFoundation
import SwiftUI
import Vision

/// A user-initiated, single-use camera session. No image or raw QR payload
/// is persisted or passed to the dashboard. Paste is always available there.
struct MacPairingCameraView: View {
    let onKey: (String) -> Void
    let onCancel: () -> Void
    @StateObject private var capture = MacPairingCapture()

    var body: some View {
        VStack(spacing: 16) {
            Text("Scan iPhone public pairing QR").font(.headline)
            MacCameraPreview(session: capture.session)
                .frame(width: 420, height: 280)
            Text(capture.status).multilineTextAlignment(.center)
            Button("Cancel / use paste instead", action: onCancel)
                .keyboardShortcut(.cancelAction)
        }
        .padding(20)
        .task {
            let granted = await AVCaptureDevice.requestAccess(for: .video)
            guard !Task.isCancelled else { return }
            if granted {
                capture.start(onKey: onKey)
            } else {
                capture.status = "Camera access unavailable. Cancel and paste the iPhone pairing payload instead."
            }
        }
        .onDisappear { capture.stop() }
    }
}

private struct MacCameraPreview: NSViewRepresentable {
    let session: AVCaptureSession

    func makeNSView(context: Context) -> NSView {
        let view = NSView()
        view.wantsLayer = true
        let preview = AVCaptureVideoPreviewLayer(session: session)
        preview.videoGravity = .resizeAspect
        view.layer = preview
        return view
    }

    func updateNSView(_ view: NSView, context: Context) {}
}

/// Session configuration, frames and the one-shot delivery flag are confined
/// to a serial queue. UI callbacks and the active flag are confined to main.
private final class MacPairingCapture: NSObject, ObservableObject,
    AVCaptureVideoDataOutputSampleBufferDelegate {
    let session = AVCaptureSession()
    @Published var status = "Checking camera access…"
    private let queue = DispatchQueue(label: "com.gavindu.agent.mac-pairing-camera")
    private var active = false
    private var onKey: ((String) -> Void)?
    private var delivered = false

    func start(onKey: @escaping (String) -> Void) {
        guard !active else { return }
        active = true
        self.onKey = onKey
        queue.async {
            guard let device = AVCaptureDevice.default(for: .video),
                  let input = try? AVCaptureDeviceInput(device: device) else {
                self.reportUnavailable()
                return
            }
            self.session.beginConfiguration()
            let output = AVCaptureVideoDataOutput()
            guard self.session.canAddInput(input), self.session.canAddOutput(output) else {
                self.session.commitConfiguration()
                self.reportUnavailable()
                return
            }
            self.session.addInput(input)
            output.alwaysDiscardsLateVideoFrames = true
            output.setSampleBufferDelegate(self, queue: self.queue)
            self.session.addOutput(output)
            self.session.commitConfiguration()
            self.session.startRunning()
            if !self.session.isRunning {
                self.reportUnavailable()
                return
            }
            DispatchQueue.main.async {
                guard self.active else { return }
                self.status = "Show exactly one iPhone pairing QR code to the camera."
            }
        }
    }

    private func reportUnavailable() {
        DispatchQueue.main.async {
            guard self.active else { return }
            self.status = "Camera unavailable. Cancel and paste the iPhone pairing payload instead."
        }
    }

    func stop() {
        active = false
        onKey = nil
        queue.async {
            self.delivered = true
            if self.session.isRunning { self.session.stopRunning() }
        }
    }

    func captureOutput(_ output: AVCaptureOutput, didOutput sampleBuffer: CMSampleBuffer,
                       from connection: AVCaptureConnection) {
        guard !delivered, let buffer = CMSampleBufferGetImageBuffer(sampleBuffer) else { return }
        let request = VNDetectBarcodesRequest()
        request.symbologies = [.qr]
        guard (try? VNImageRequestHandler(cvPixelBuffer: buffer, options: [:])
            .perform([request])) != nil,
              let observations = request.results,
              observations.count == 1,
              let text = observations[0].payloadStringValue,
              let key = IPhonePairingImportPolicy.cameraPublicKey(from: [text]) else { return }
        delivered = true
        DispatchQueue.main.async {
            guard self.active else { return }
            let callback = self.onKey
            self.stop()
            callback?(key)
        }
    }
}

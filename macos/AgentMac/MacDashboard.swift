import AppKit
import CoreImage
import CoreImage.CIFilterBuiltins
import SwiftUI

struct MacDashboard: View {
    @AppStorage("macWireGuardPublicKey") private var publicKey = ""
    @AppStorage("macWireGuardEndpoint") private var endpoint = ""
    @State private var iphonePublicKey = ""
    @State private var iphonePairingText = ""
    @State private var validationMessage: String?
    @State private var cameraScan: CameraScan?

    private struct CameraScan: Identifiable {
        let id = UUID()
    }

    private var profile: ServerProfile? {
        try? ServerProfile(publicKey: publicKey, endpoint: endpoint).validated()
    }

    private var validatedIPhoneKey: String? {
        IPhonePairingImportPolicy.validatedPublicKey(iphonePublicKey)
    }

    private var peerStanza: String {
        guard let key = validatedIPhoneKey else {
            return "Enter a valid, nonzero canonical iPhone public key to prepare its WireGuard peer."
        }
        return """
        [Peer]
        # Security Agent iPhone (public material only)
        PublicKey = \(key)
        AllowedIPs = 10.8.0.2/32, fd86:ea04:1111::2/128
        """
    }

    var body: some View {
        HStack(alignment: .top, spacing: 28) {
            Form {
                Section("Mac Mini server") {
                    TextField("Public key (base64)", text: $publicKey)
                        .textFieldStyle(.roundedBorder)
                    TextField("home.example.net:51820", text: $endpoint)
                        .textFieldStyle(.roundedBorder)
                    Text("Retrieve the server's public key with sudo wg show <interface> public-key. Never paste a private key.")
                        .font(.caption).foregroundStyle(.secondary)
                }
                Section("iPhone peer registration") {
                    Button("Scan iPhone pairing QR with camera") {
                        iphonePublicKey = ""
                        iphonePairingText = ""
                        validationMessage = nil
                        cameraScan = CameraScan()
                    }
                    TextField("Paste iPhone pairing QR JSON", text: $iphonePairingText)
                        .textFieldStyle(.roundedBorder)
                    Button("Import iPhone pairing payload") {
                        if let key = IPhonePairingImportPolicy.decodePublicKey(
                            from: iphonePairingText
                        ) {
                            iphonePublicKey = key
                            validationMessage = nil
                        } else {
                            // Do not reflect untrusted QR JSON, endpoints or
                            // arbitrary decoder errors into diagnostics.
                            iphonePublicKey = ""
                            validationMessage = "Invalid iPhone QR: expected version 1 and a canonical 32-byte public key."
                        }
                        iphonePairingText = ""
                    }
                    TextField("iPhone public key", text: $iphonePublicKey)
                        .textFieldStyle(.roundedBorder)
                    TextEditor(text: .constant(peerStanza))
                        .font(.system(.caption, design: .monospaced))
                        .frame(height: 116)
                    Button("Copy peer configuration") {
                        NSPasteboard.general.clearContents()
                        NSPasteboard.general.setString(peerStanza, forType: .string)
                    }
                    .disabled(validatedIPhoneKey == nil)
                    Text("Add the peer stanza to the Mac's actual WireGuard server config and activate it. This UI does not run sudo.")
                        .font(.caption).foregroundStyle(.secondary)
                }
                if let validationMessage {
                    Text(validationMessage).foregroundStyle(.red)
                }
            }
            .frame(minWidth: 330)

            VStack(spacing: 14) {
                Text("Mac pairing QR").font(.title3.bold())
                if let profile,
                   let qr = try? PairingQRCode(
                    kind: .mac, publicKey: profile.publicKey, endpoint: profile.endpoint
                   ).encodedText(),
                   let image = QRCodeRenderer.render(qr) {
                    Image(nsImage: image)
                        .interpolation(.none)
                        .resizable()
                        .scaledToFit()
                        .frame(width: 215, height: 215)
                    Text("Scan from iPhone → Pair")
                        .font(.caption).foregroundStyle(.secondary)
                    Text("SHA-256 key fingerprint")
                        .font(.caption.bold())
                    Text((try? profile.publicKeyFingerprint()) ?? "Unavailable")
                        .font(.system(.caption2, design: .monospaced))
                        .textSelection(.enabled)
                        .multilineTextAlignment(.center)
                } else {
                    ContentUnavailableView(
                        "Server details needed",
                        systemImage: "qrcode",
                        description: Text("Enter a valid 32-byte base64 public key and UDP endpoint.")
                    )
                    .frame(width: 230, height: 245)
                }
                Text("Verify the public key on both devices before trusting the QR.")
                    .font(.caption).multilineTextAlignment(.center)
                    .frame(maxWidth: 250)
            }
        }
        .padding(25)
        .sheet(item: $cameraScan) { scan in
            MacPairingCameraView { key in
                guard cameraScan?.id == scan.id else { return }
                iphonePublicKey = key
                validationMessage = nil
                cameraScan = nil
            } onCancel: {
                guard cameraScan?.id == scan.id else { return }
                cameraScan = nil
            }
        }
    }
}

private enum QRCodeRenderer {
    static func render(_ string: String) -> NSImage? {
        let filter = CIFilter.qrCodeGenerator()
        filter.message = Data(string.utf8)
        filter.correctionLevel = "M"
        guard let output = filter.outputImage,
              let cg = CIContext().createCGImage(output, from: output.extent) else { return nil }
        return NSImage(cgImage: cg, size: NSSize(width: cg.width, height: cg.height))
    }
}

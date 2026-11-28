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
    @State private var previewGeneration = UUID()
    @State private var peerConfirmation = PairingConfirmationGate<MacPeerConfirmationContext>()

    private struct CameraScan: Identifiable {
        let id = UUID()
    }

    private var profile: ServerProfile? {
        try? ServerProfile(publicKey: publicKey, endpoint: endpoint).validated()
    }

    private var validatedIPhoneKey: String? {
        IPhonePairingImportPolicy.validatedPublicKey(iphonePublicKey)
    }

    private var peerPreview: MacPeerConfirmationContext? {
        guard cameraScan == nil, iphonePairingText.isEmpty,
              let profile, let key = validatedIPhoneKey,
              key != profile.publicKey else { return nil }
        return MacPeerConfirmationContext(serverPublicKey: profile.publicKey,
            endpoint: profile.endpoint, clientPublicKey: key, generation: previewGeneration)
    }

    private var peerStanza: String {
        guard let preview = peerPreview, peerConfirmation.permitsSave(preview) else {
            return "Verify the iPhone fingerprint on its trusted screen to reveal the single-device peer preview."
        }
        return peerStanza(for: preview)
    }

    private func peerStanza(for preview: MacPeerConfirmationContext) -> String {
        """
        [Peer]
        # Security Agent iPhone (public material only)
        PublicKey = \(preview.clientPublicKey)
        AllowedIPs = 10.8.0.2/32, fd86:ea04:1111::2/128
        """
    }

    private func invalidatePeerApproval() {
        peerConfirmation.reset()
        previewGeneration = UUID()
    }

    // Invalidate synchronously before accepting an edit, including A→B→A.
    private func editing(_ binding: Binding<String>) -> Binding<String> {
        Binding(get: { binding.wrappedValue }, set: { value in
            invalidatePeerApproval()
            binding.wrappedValue = value
        })
    }

    var body: some View {
        HStack(alignment: .top, spacing: 28) {
            Form {
                Section("Mac Mini server") {
                    TextField("Public key (base64)", text: editing($publicKey))
                        .textFieldStyle(.roundedBorder)
                    TextField("home.example.net:51820", text: editing($endpoint))
                        .textFieldStyle(.roundedBorder)
                    Text("Retrieve the server's public key with sudo wg show <interface> public-key. Never paste a private key.")
                        .font(.caption).foregroundStyle(.secondary)
                }
                Section("iPhone peer registration") {
                    Button("Scan iPhone pairing QR with camera") {
                        invalidatePeerApproval()
                        iphonePublicKey = ""
                        iphonePairingText = ""
                        validationMessage = nil
                        cameraScan = CameraScan()
                    }
                    TextField("Paste iPhone pairing QR JSON", text: editing($iphonePairingText))
                        .textFieldStyle(.roundedBorder)
                    Button("Import iPhone pairing payload") {
                        invalidatePeerApproval()
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
                    TextField("iPhone public key", text: editing($iphonePublicKey))
                        .textFieldStyle(.roundedBorder)
                    if let preview = peerPreview,
                       let fingerprint = try? WireGuardPublicFingerprint.display(for: preview.clientPublicKey) {
                        Text("iPhone SHA-256 key fingerprint")
                            .font(.caption.bold())
                        Text(fingerprint)
                            .font(.system(.caption2, design: .monospaced))
                            .textSelection(.enabled)
                        Text("Compare the entire fingerprint with the trusted iPhone screen, not with the QR or pasted key alone.")
                            .font(.caption).foregroundStyle(.secondary)
                        Toggle("I verified the fingerprint on this iPhone", isOn: Binding(
                            get: { peerConfirmation.permitsSave(peerPreview) },
                            set: { confirmed in
                                // A delayed event from an old rendered preview
                                // cannot approve a newer selection.
                                guard peerPreview == preview else {
                                    invalidatePeerApproval()
                                    return
                                }
                                peerConfirmation.setConfirmed(confirmed, for: preview)
                            }
                        ))
                    }
                    TextEditor(text: .constant(peerStanza))
                        .font(.system(.caption, design: .monospaced))
                        .frame(height: 116)
                    Button("Copy peer configuration") {
                        guard let preview = peerPreview,
                              peerConfirmation.permitsSave(preview) else { return }
                        NSPasteboard.general.clearContents()
                        NSPasteboard.general.setString(peerStanza(for: preview), forType: .string)
                    }
                    .disabled(!peerConfirmation.permitsSave(peerPreview))
                    Text("Single-device preview only: every current iPhone uses 10.8.0.2. An administrator must verify both addresses are unassigned or already belong to this exact key before applying the stanza. Do not add another phone at this address. This UI does not run sudo.")
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
        .onChange(of: publicKey) { _, _ in invalidatePeerApproval() }
        .onChange(of: endpoint) { _, _ in invalidatePeerApproval() }
        .onChange(of: iphonePublicKey) { _, _ in invalidatePeerApproval() }
        .onChange(of: iphonePairingText) { _, _ in invalidatePeerApproval() }
        .sheet(item: $cameraScan) { scan in
            MacPairingCameraView { key in
                guard cameraScan?.id == scan.id else { return }
                invalidatePeerApproval()
                iphonePublicKey = key
                validationMessage = nil
                cameraScan = nil
            } onCancel: {
                guard cameraScan?.id == scan.id else { return }
                invalidatePeerApproval()
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

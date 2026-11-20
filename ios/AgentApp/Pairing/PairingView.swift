import SwiftUI

struct PairingView: View {
    @ObservedObject var tunnel: TunnelManager
    @State private var ownPublicKey: String?
    @State private var pairingError: String?
    @State private var isScanning = false
    @State private var macPreview: ServerProfile?
    @State private var fingerprintConfirmed = false

    var body: some View {
        Form {
            Section("1. Share this iPhone's public key") {
                if let ownPublicKey,
                   let payload = try? PairingQRCode(kind: .iphone, publicKey: ownPublicKey).encodedText() {
                    QRCodeImage(text: payload)
                        .frame(maxWidth: 220, maxHeight: 220)
                        .frame(maxWidth: .infinity)
                    Text(ownPublicKey)
                        .font(.caption.monospaced())
                        .textSelection(.enabled)
                    ShareLink("Share public key", item: ownPublicKey)
                } else {
                    ProgressView("Preparing secure identity…")
                }
                Text("On the Mac Mini, register the displayed public key as a peer at 10.8.0.2/32.")
                    .foregroundStyle(.secondary)
            }

            Section("2. Scan the Mac Mini QR") {
                Button("Scan Mac Mini pairing QR") { isScanning = true }
                if let preview = macPreview {
                    LabeledContent("Endpoint", value: preview.endpoint)
                    LabeledContent("Mac public key", value: preview.publicKey)
                        .font(.caption.monospaced())
                    if let fingerprint = try? preview.publicKeyFingerprint() {
                        LabeledContent("SHA-256 key fingerprint", value: fingerprint)
                            .font(.caption.monospaced())
                            .textSelection(.enabled)
                    }
                    Text("Compare the entire fingerprint with the trusted Mac Mini screen, not with this QR code alone.")
                        .font(.footnote).foregroundStyle(.secondary)
                    Toggle("I verified the fingerprint on my Mac", isOn: $fingerprintConfirmed)
                    Button("Trust Mac and save VPN") {
                        guard fingerprintConfirmed else { return }
                        tunnel.save(preview)
                        macPreview = nil
                        fingerprintConfirmed = false
                    }
                    .disabled(!fingerprintConfirmed)
                    .buttonStyle(.borderedProminent)
                }
                if let current = tunnel.profile {
                    LabeledContent("Currently paired", value: current.endpoint)
                }
            }
        }
        .navigationTitle("Pair devices")
        .task {
            do { ownPublicKey = try SharedKeychain.publicKeyBase64() }
            catch { pairingError = error.localizedDescription }
        }
        .sheet(isPresented: $isScanning) {
            NavigationStack {
                QRScannerView { scanned in
                    isScanning = false
                    fingerprintConfirmed = false
                    macPreview = nil
                    do { macPreview = try PairingQRCode.decodeMac(scanned) }
                    catch { pairingError = error.localizedDescription }
                }
                .toolbar { ToolbarItem(placement: .topBarTrailing) {
                    Button("Cancel") { isScanning = false }
                } }
            }
        }
        .alert("Pairing error", isPresented: Binding(
            get: { pairingError != nil },
            set: { if !$0 { pairingError = nil } }
        )) {
            Button("OK") { pairingError = nil }
        } message: {
            Text(pairingError ?? "")
        }
    }
}

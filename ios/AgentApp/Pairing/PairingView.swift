import SwiftUI

struct PairingView: View {
    @ObservedObject var tunnel: TunnelManager
    @State private var ownPublicKey: String?
    @State private var pairingError: String?
    @State private var isScanning = false
    @State private var macPreview: ServerProfile?

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
                    Text("Verify this key against the value displayed on your trusted Mac.")
                        .font(.footnote).foregroundStyle(.secondary)
                    Button("Trust Mac and save VPN") {
                        tunnel.save(preview)
                        macPreview = nil
                    }
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

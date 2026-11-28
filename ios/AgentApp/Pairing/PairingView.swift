import SwiftUI

struct PairingView: View {
    @ObservedObject var tunnel: TunnelManager
    @State private var ownPublicKey: String?
    @State private var pairingError: String?
    @State private var isScanning = false
    @State private var macPreview: ServerProfile?
    @State private var confirmation = PairingConfirmationGate<ServerProfile>()

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
                    if let fingerprint = try? WireGuardPublicFingerprint.display(for: ownPublicKey) {
                        LabeledContent("iPhone SHA-256 key fingerprint", value: fingerprint)
                            .font(.caption.monospaced())
                            .textSelection(.enabled)
                        Text("Have the Mac administrator compare the entire fingerprint with this trusted iPhone screen before copying the peer configuration.")
                            .font(.footnote).foregroundStyle(.secondary)
                    }
                    ShareLink("Share public key", item: ownPublicKey)
                } else {
                    ProgressView("Preparing secure identity…")
                }
                Text("Single-device pairing only: ask the Mac administrator to verify 10.8.0.2/32 is available or already assigned to this exact public key before registering it. Do not replace another phone’s peer.")
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
                    Toggle("I verified the fingerprint on my Mac", isOn: Binding(
                        get: { confirmation.permitsSave(macPreview) },
                        set: { newValue in
                            confirmation.setConfirmed(newValue, for: macPreview)
                        }
                    ))
                    Button("Trust Mac and save VPN") {
                        guard macPreview == preview, confirmation.permitsSave(macPreview) else { return }
                        // Keep the scan + fingerprint confirmation available
                        // until native preferences and App Group commit succeed.
                        // A denied active-session save must not force a re-scan.
                        tunnel.save(preview)
                    }
                    .disabled(!confirmation.permitsSave(preview))
                    .buttonStyle(.borderedProminent)
                    if let error = tunnel.errorMessage {
                        Text(error)
                            .font(.footnote)
                            .foregroundStyle(.red)
                    }
                }
                if let current = tunnel.profile {
                    LabeledContent("Currently paired", value: current.endpoint)
                }
            }
        }
        .navigationTitle("Pair devices")
        .onChange(of: tunnel.profile) { _, committed in
            guard let macPreview, committed == macPreview else { return }
            self.macPreview = nil
            confirmation.reset()
        }
        .task {
            do { ownPublicKey = try SharedKeychain.publicKeyBase64() }
            catch { pairingError = error.localizedDescription }
        }
        .sheet(isPresented: $isScanning) {
            NavigationStack {
                QRScannerView { scanned in
                    isScanning = false
                    confirmation.reset()
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

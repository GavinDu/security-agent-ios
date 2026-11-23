import Foundation

// BoringTun 0.7.1 wireguard_ffi.h is imported through BoringTunBridge.h.
// A Tunn is a protocol engine, NOT an iOS utun/UDP stack. All calls to this
// object must be serialized on BoringTunTransport's private dispatch queue.
enum BoringTunAction {
    case done
    case sendToNetwork(Data)
    case writeIPv4(Data)
    case writeIPv6(Data)
}

enum BoringTunError: LocalizedError {
    case invalidKey
    case initializationFailed
    case invalidPacket
    case engineError
    case invalidResponse
    case stopped
    case handshakeTimedOut
    case networkPathTimedOut
    case packetFlowWriteFailed

    var errorDescription: String? {
        switch self {
        case .invalidKey: return "Invalid WireGuard key material."
        case .initializationFailed: return "Unable to initialize the Rust WireGuard engine."
        case .invalidPacket: return "Invalid packet length or protocol."
        case .engineError: return "Rust WireGuard engine rejected a packet."
        case .invalidResponse: return "Rust WireGuard FFI returned an invalid response."
        case .stopped: return "WireGuard tunnel stopped."
        case .handshakeTimedOut: return "WireGuard peer handshake timed out."
        case .networkPathTimedOut: return "WireGuard UDP network path did not recover; disconnect and reconnect to resolve the endpoint again."
        case .packetFlowWriteFailed: return "The iOS VPN packet interface rejected a decrypted packet; reconnect the tunnel."
        }
    }
}

final class BoringTunCodec {
    // Upstream BoringTun C header: MAX_WIREGUARD_PACKET_SIZE = 65536 + 64.
    private static let bufferSize = 65_600
    private let handle: OpaquePointer

    init(privateKey: Data, serverKey: String, presharedKey: Data?) throws {
        // Validate at the actual Swift-to-Rust FFI boundary, regardless
        // of how the caller obtained or persisted the public profile.
        guard BoringTunKeyInputPolicy.accepts(
            privateKey: privateKey, serverPublicKey: serverKey, presharedKey: presharedKey
        ) else {
            throw BoringTunError.invalidKey
        }
        let privateBase64 = privateKey.base64EncodedString()
        let pskBase64 = presharedKey?.base64EncodedString()
        let ptr: OpaquePointer? = privateBase64.withCString { privateCString in
            serverKey.withCString { publicCString in
                if let pskBase64 {
                    return pskBase64.withCString { pskCString in
                        new_tunnel(privateCString, publicCString, pskCString, 25, 0)
                    }
                }
                return new_tunnel(privateCString, publicCString, nil, 25, 0)
            }
        }
        guard let ptr else { throw BoringTunError.initializationFailed }
        handle = ptr
    }

    deinit { tunnel_free(handle) }

    private func run(_ invoke: (UnsafeMutablePointer<UInt8>) -> wireguard_result) throws -> BoringTunAction {
        var output = [UInt8](repeating: 0, count: Self.bufferSize)
        let response = output.withUnsafeMutableBufferPointer { buffer in
            invoke(buffer.baseAddress!)
        }
        // size_t carries an error code for WIREGUARD_ERROR, not packet bytes.
        // Dispatch first: converting a negative Rust error as unsigned size_t
        // to Swift Int may trap before we even reach the error case.
        let operation = Int(response.op.rawValue)
        switch operation {
        case 0:
            // Rust TunnResult::Done must report no output bytes. Never
            // silently accept a malformed local C ABI result.
            guard BoringTunFFIDonePolicy.acceptsDoneSize(response.size) else {
                throw BoringTunError.invalidResponse
            }
            return .done
        // Rust uses size as an error *code* for op 2, not packet bytes.
        case 2:
            throw BoringTunError.engineError
        case 1, 4, 6:
            // Only output operations may interpret size as a byte count.
            // Check in native size_t before converting to Int.
            guard response.size > 0, response.size <= numericCast(output.count) else {
                throw BoringTunError.invalidResponse
            }
            let count = Int(response.size)
            let data = Data(output.prefix(count))
            switch operation {
            case 1: return .sendToNetwork(data)
            case 4: return .writeIPv4(data)
            default: return .writeIPv6(data)
            }
        default:
            throw BoringTunError.invalidResponse
        }
    }

    func forceHandshake() throws -> BoringTunAction {
        try run { wireguard_force_handshake(handle, $0, UInt32(Self.bufferSize)) }
    }

    func tick() throws -> BoringTunAction {
        try run { wireguard_tick(handle, $0, UInt32(Self.bufferSize)) }
    }

    func encapsulate(_ packet: Data) throws -> BoringTunAction {
        guard !packet.isEmpty, packet.count <= 65_536 else {
            throw BoringTunError.invalidPacket
        }
        return try packet.withUnsafeBytes { bytes in
            let pointer = bytes.bindMemory(to: UInt8.self).baseAddress!
            return try run {
                wireguard_write(handle, pointer, UInt32(packet.count), $0, UInt32(Self.bufferSize))
            }
        }
    }

    func decapsulate(_ datagram: Data) throws -> BoringTunAction {
        guard !datagram.isEmpty, datagram.count <= Self.bufferSize else {
            throw BoringTunError.invalidPacket
        }
        return try datagram.withUnsafeBytes { bytes in
            let pointer = bytes.bindMemory(to: UInt8.self).baseAddress!
            return try run {
                wireguard_read(handle, pointer, UInt32(datagram.count), $0, UInt32(Self.bufferSize))
            }
        }
    }

    var hasAuthenticatedHandshake: Bool {
        wireguard_stats(handle).time_since_last_handshake >= 0
    }
}

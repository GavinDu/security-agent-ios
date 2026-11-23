import Foundation

/// Upstream BoringTun 0.7.1 ffi/mod.rs returns TunnResult::Done as
/// WIREGUARD_DONE (op 0) with size = 0. Nonzero size here is a
/// malformed local C ABI result, not a valid packet or error code.
///
/// The Swift C importer exposes this ABI size_t as Int; do not cast an
/// error code to an output length. WIREGUARD_ERROR (op 2) encodes an error
/// code in size; the BoringTunCodec handles it separately without
/// interpreting it as a packet byte count.
enum BoringTunFFIDonePolicy {
    static func acceptsDoneSize(_ size: Int) -> Bool {
        size == 0
    }
}

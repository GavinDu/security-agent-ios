#!/usr/bin/env python3
"""Real host C-ABI smoke for the pinned BoringTun Rust protocol engine.

Two ephemeral test peers perform a handshake and encrypted IPv4 exchange.
This is NOT an iPhone PacketTunnel, an Apple signing check or a liveness soak.
"""
import base64
import ctypes
import sys


MAX_PACKET = 65_600
DONE, NETWORK, ERROR, IPV4, IPV6 = 0, 1, 2, 4, 6


class Result(ctypes.Structure):
    _fields_ = [("op", ctypes.c_int), ("size", ctypes.c_size_t)]


class Key(ctypes.Structure):
    _fields_ = [("key", ctypes.c_uint8 * 32)]


def check_action(result, buf):
    if result.op == ERROR:
        raise AssertionError(f"BoringTun protocol error code {result.size}")
    if result.op not in (DONE, NETWORK, IPV4, IPV6):
        raise AssertionError(f"Unknown FFI result operation: {result.op}")
    if result.op != DONE and not (0 < result.size <= MAX_PACKET):
        raise AssertionError(f"Invalid FFI output buffer size {result.size}")
    return result.op, bytes(buf.raw[:result.size]) if result.op != DONE else b""


def handshake_roundtrip(lib):
    lib.x25519_public_key.argtypes = [Key]
    lib.x25519_public_key.restype = Key
    lib.new_tunnel.argtypes = [
        ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p,
        ctypes.c_uint16, ctypes.c_uint32
    ]
    lib.new_tunnel.restype = ctypes.c_void_p
    lib.tunnel_free.argtypes = [ctypes.c_void_p]
    lib.tunnel_free.restype = None
    lib.wireguard_force_handshake.argtypes = [
        ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint32
    ]
    lib.wireguard_force_handshake.restype = Result
    for name in ("wireguard_read", "wireguard_write"):
        function = getattr(lib, name)
        function.argtypes = [
            ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint32,
            ctypes.c_void_p, ctypes.c_uint32
        ]
        function.restype = Result

    # Fixed *non-production* test vectors; never use these in actual VPN keys.
    client_private = bytes(range(1, 33))
    server_private = bytes(range(33, 65))
    client_public = bytes(
        lib.x25519_public_key(Key((ctypes.c_uint8 * 32)(*client_private))).key
    )
    server_public = bytes(
        lib.x25519_public_key(Key((ctypes.c_uint8 * 32)(*server_private))).key
    )
    client = lib.new_tunnel(
        base64.b64encode(client_private),
        base64.b64encode(server_public),
        None, 25, 1
    )
    server = lib.new_tunnel(
        base64.b64encode(server_private),
        base64.b64encode(client_public),
        None, 25, 2
    )
    assert client is not None and server is not None, "Failed to create test peers"

    def initiate(tunnel):
        dst = ctypes.create_string_buffer(MAX_PACKET)
        result = lib.wireguard_force_handshake(tunnel, dst, MAX_PACKET)
        return check_action(result, dst)

    def exchange(tunnel, input_datagram):
        src = ctypes.create_string_buffer(input_datagram, len(input_datagram))
        dst = ctypes.create_string_buffer(MAX_PACKET)
        result = lib.wireguard_read(tunnel, src, len(input_datagram), dst, MAX_PACKET)
        return check_action(result, dst)

    def send_ip(tunnel, input_packet):
        src = ctypes.create_string_buffer(input_packet, len(input_packet))
        dst = ctypes.create_string_buffer(MAX_PACKET)
        result = lib.wireguard_write(tunnel, src, len(input_packet), dst, MAX_PACKET)
        return check_action(result, dst)

    try:
        op, initiation = initiate(client)
        assert op == NETWORK, f"Expected handshake initiation, got op={op}"
        op, response = exchange(server, initiation)
        assert op == NETWORK, f"Expected handshake response, got op={op}"
        op, confirm = exchange(client, response)
        assert op in (DONE, NETWORK), f"Unexpected handshake confirmation {op}"
        if op == NETWORK:
            back_op, _ = exchange(server, confirm)
            assert back_op in (DONE, NETWORK), f"Unexpected peer confirmation {back_op}"

        # Minimal illustrative IPv4 datagram; this is NOT an internet packet test.
        ipv4 = bytes.fromhex("4500001400010000401100000a0800020a080001")
        op, encrypted = send_ip(client, ipv4)
        assert op == NETWORK, f"Expected encrypted data, got op={op}"
        op, recovered = exchange(server, encrypted)
        assert op == IPV4, f"Expected decrypted IPv4 packet, got op={op}"
        assert recovered == ipv4, "WireGuard decrypted payload differs from input"

        op, encrypted = send_ip(server, ipv4)
        assert op == NETWORK, f"Expected reverse encrypted data, got op={op}"
        op, recovered = exchange(client, encrypted)
        assert op == IPV4 and recovered == ipv4, "Reverse WireGuard packet mismatch"
        print("BoringTun C ABI: test peer handshake and bidirectional IPv4 OK")
    finally:
        lib.tunnel_free(client)
        lib.tunnel_free(server)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("usage: boringtun_ffi_smoke.py PATH_TO_LIBBORINGTUN_SO")
    handshake_roundtrip(ctypes.CDLL(sys.argv[1]))

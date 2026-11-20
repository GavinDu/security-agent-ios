#!/usr/bin/env python3
"""Bounded malformed-UDP corpus against the *real* pinned BoringTun C ABI.

A passing host test is not evidence for signed-iPhone PacketTunnel safety.
"""
import base64
import ctypes
import random
import sys

from boringtun_ffi_smoke import Result, Key, MAX_PACKET, DONE, ERROR, NETWORK, IPV4, IPV6


def exercise(path):
    lib = ctypes.CDLL(path)
    lib.x25519_public_key.argtypes = [Key]
    lib.x25519_public_key.restype = Key
    lib.new_tunnel.argtypes = [
        ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p,
        ctypes.c_uint16, ctypes.c_uint32
    ]
    lib.new_tunnel.restype = ctypes.c_void_p
    lib.tunnel_free.argtypes = [ctypes.c_void_p]
    lib.tunnel_free.restype = None
    lib.wireguard_read.argtypes = [
        ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint32,
        ctypes.c_void_p, ctypes.c_uint32
    ]
    lib.wireguard_read.restype = Result

    private = bytes(range(1, 33))
    remote_secret = Key((ctypes.c_uint8 * 32)(*bytes(range(33, 65))))
    remote_public = bytes(lib.x25519_public_key(remote_secret).key)
    tunnel = lib.new_tunnel(base64.b64encode(private), base64.b64encode(remote_public),
                            None, 25, 100)
    assert tunnel, "Could not initialize nonproduction test tunnel"

    try:
        invalid = lib.new_tunnel(b"not_base64", b"invalid_key", None, 25, 101)
        assert not invalid, "BoringTun accepted malformed WireGuard key material"

        lengths = [1, 2, 3, 4, 5, 7, 8, 12, 16, 20, 28, 32, 64,
                   92, 128, 256, 512, 1024, 2048, 8192, MAX_PACKET]
        seed = random.Random(0xB047)
        corpus = [
            bytes([0]) * n for n in lengths
        ] + [
            bytes([255]) * n for n in lengths
        ] + [
            bytes((i % 256 for i in range(n))) for n in lengths
        ]
        # Diverse deterministic malformed datagrams; never print payloads.
        corpus.extend(seed.randbytes(seed.choice(lengths)) for _ in range(200))

        dst = ctypes.create_string_buffer(MAX_PACKET)
        for packet in corpus:
            src = ctypes.create_string_buffer(packet, len(packet))
            result = lib.wireguard_read(tunnel, src, len(packet), dst, MAX_PACKET)
            assert result.op in (DONE, ERROR, NETWORK, IPV4, IPV6), (
                f"Unexpected BoringTun FFI operation {result.op}"
            )
            # Error result.size is an error code, not a byte count. Do NOT
            # cast/interpret it as an output length (see Swift regression #60).
            if result.op in (NETWORK, IPV4, IPV6):
                assert 0 < result.size <= MAX_PACKET, "Out-of-range FFI output"
        print(f"BoringTun malformed UDP C ABI corpus: {len(corpus)} cases without crash")
    finally:
        lib.tunnel_free(tunnel)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("usage: boringtun_ffi_malformed.py LIBBORINGTUN_SO")
    exercise(sys.argv[1])

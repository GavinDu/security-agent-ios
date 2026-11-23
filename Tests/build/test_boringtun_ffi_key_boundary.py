"""Rust BoringTun Swift C FFI key inputs validated before new_tunnel allocation."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
CODEC = (ROOT / "ios/PacketTunnel/BoringTunCodec.swift").read_text()
POLICY = (ROOT / "Shared/BoringTunKeyInputPolicy.swift").read_text()
WF = (ROOT / ".github/workflows/validate.yml").read_text()
KEYCHAIN = (ROOT / "Shared/SecretStore.swift").read_text()
SMOKE = (ROOT / "Tests/build/boringtun_key_input_smoke.swift").read_text()
NATIVE = (ROOT / "Tests/iOS/BoringTunKeyInputPolicyTests.swift").read_text()

class BoringTunFFIKeyBoundaryTests(unittest.TestCase):
    def test_transport_code_checks_canonical_key_before_rust_allocation(self):
        init = CODEC.split("init(privateKey: Data, serverKey: String, presharedKey: Data?) throws", 1)[1]
        self.assertLess(init.index("BoringTunKeyInputPolicy.accepts("), init.index("new_tunnel("))
        self.assertIn("throw BoringTunError.invalidKey", init)
        self.assertNotIn("let serverRaw = Data(base64Encoded: serverKey)", init)
        self.assertNotIn("print(", init)
        self.assertNotIn("NSLog(", init)

    def test_bound_before_decode_and_disallow_zero_keys(self):
        self.assertLess(POLICY.index("serverPublicKey.utf8.count == 44"),
                        POLICY.index("Data(base64Encoded: serverPublicKey)"))
        self.assertIn("key.base64EncodedString() == serverPublicKey", POLICY)
        self.assertIn("privateKey.contains(where: { $0 != 0 })", POLICY)
        self.assertIn("key.contains(where: { $0 != 0 })", POLICY)
        self.assertIn("presharedKey == nil || presharedKey?.count == 32", POLICY)

    def test_present_psk_must_be_nonzero_at_keychain_and_ffi_boundary(self):
        self.assertIn(
            "presharedKey?.contains(where: { $0 != 0 }) == true", POLICY
        )
        keychain_read = KEYCHAIN.split(
            "static func optionalPreSharedKey() throws -> Data?", 1
        )[1].split("// PSKs must be provisioned", 1)[0]
        self.assertLess(
            keychain_read.index("guard data.count == 32"),
            keychain_read.index("guard data.contains(where: { $0 != 0 })")
        )
        self.assertIn("throw KeychainError.invalidSecret", keychain_read)
        self.assertIn("guard let data = try read(pskAccount) else { return nil }",
                      keychain_read)
        self.assertIn("Data(repeating: 0, count: 32)", SMOKE)
        self.assertIn("!accepts(secret, peer, Data(repeating: 0, count: 32))", SMOKE)
        self.assertIn("Data(repeating: 0, count: 32)", NATIVE)
        self.assertIn("Data(repeating: 0x7B, count: 32)", NATIVE)

    def test_full_ffi_c_abi_typecheck_and_production_swift_smoke(self):
        self.assertIn("Shared/BoringTunKeyInputPolicy.swift", WF)
        self.assertIn("Tests/build/boringtun_key_input_smoke.swift", WF)
        self.assertTrue((ROOT / "Tests/iOS/BoringTunKeyInputPolicyTests.swift").exists())

if __name__ == "__main__":
    unittest.main()

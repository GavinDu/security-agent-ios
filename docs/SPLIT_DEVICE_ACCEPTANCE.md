# Split-tunnel signed-device acceptance (#28 / Epic #192)

This is the only component acceptance gate remaining after the merged DNS
implementation (#95, PRs #196/#197). Epic E #195 / #3 consumes the
redacted result for integration; it does not duplicate component testing.
No full-tunnel enablement, Go implementation, production gateway rollout,
or physical-device result is implied by this procedure.

## Prerequisites

- Owner-controlled, signed iPhone with the tested app commit and PacketTunnel
  entitlement; independently provisioned Rust BoringTun 0.7.1 reference peer
  with matching keys, private agent endpoint, and controlled DNS fixtures.
- Wi-Fi, cellular and an IPv6-only/NAT64 environment. Use IPv6-capable
  Wi-Fi/cellular paths for the corresponding public IPv6 rows; otherwise
  record not_run and repeat on a capable network.
- Use only authorized test endpoints. Avoid recording keys, PSKs, public
  IPs, actual peer hostnames, identifiers, packet bodies or raw device logs.
  Observe privately and keep only sanitized route classifications, aggregate
  counters and boolean comparisons. Do not change the user's system DNS
  outside the controlled test environment.

## Procedure and pass criteria

For **each** Wi-Fi and cellular network:

1. With VPN off, capture public IPv4/IPv6 egress and DNS baseline using
   controlled test endpoints. With a valid tunnel on, compare; public
   traffic remains outside the VPN and the system resolver is not
   overridden. Report the IPv4, IPv6 and system-DNS comparisons separately.
2. Verify installed private IPv4 route is exactly 10.8.0.0/24 with no
   default routes or IPv6/DNS override, authenticated peer handshake,
   and private 10.8.0.1:8080 reachability. Observe that outer encrypted
   UDP does not enter packetFlow. Do not infer these from config alone.
3. On separate starts, use a DNS fixture returning an inner IPv4 A,
   mixed safe/unsafe answers, IPv4-mapped inner AAAA, empty response,
   resolver failure (e.g. NXDOMAIN), and a timeout. Unsafe cases must
   refuse before installing routes or allocating the codec; all failures
   must be bounded, redacted and preserve public connectivity.
4. Stop or induce a controlled connection failure; private reachability
   ceases, the private route is removed, public egress/DNS still work.

Additional independent rows:

- NAT64: demonstrate a synthesized AAAA, authenticated outer UDP,
  no outer packetFlow recursion, and unchanged ordinary public
  egress/DNS. IPv6 capability alone is not NAT64 evidence.
- DDNS: change a controlled hostname to another valid numeric address;
  stop and explicitly restart, observe a fresh pin after DNS cache
  expiry. Repeat with an unsafe answer; it must be rejected before
  settings. Current ready connections retain their pin; no automatic
  in-place repin or multi-address fallback is claimed.
- Handoff in both directions: verify the pinned session remains usable
  or fails boundedly and an explicit restart revalidates before routes.
  No unbounded retries. A ready connection retaining its pin is allowed.
- Stop while preflight is pending: no stale callback may install routes.
- Attempt an inherited/full-mode profile: it must be refused, with no
  default route installation or public DNS override.

If the available observations cannot distinguish route installation,
codec allocation or packetFlow recursion from handshake failure, mark
the relevant row not_run; do not infer an absence from a missing log.
Use an authorized diagnostic build if necessary, keeping payloads and
identifiers out of evidence; coordinate missing instrumentation with #17.
A failed case should be linked to the owning existing component issue.

## Versioned evidence report

Run from the repository root (Python 3, standard library only). Replace
the shell variables with actual metadata from the tested signed build:

    python3 scripts/validate-split-device-evidence.py template \
      --commit "$APP_COMMIT" --ios-version "$IOS_VERSION" \
      --device-model "$IPHONE_MODEL" --recorded-at "$UTC_TIMESTAMP" \
      > /tmp/split-report.json

Device model is the nonunique hardware identifier (e.g. iPhone13,4);
timestamp uses UTC YYYY-MM-DDTHH:MM:SSZ. The template starts with every
row not_run, null evidence, and signed_device=false. Only set signed_device
true after confirming a signed physical iPhone was used. For an observed
pass or fail, put the lowercase SHA-256 digest of the corresponding
**already redacted** observation artifact in evidence_sha256. Keep the
sanitized evidence available for reviewer inspection. Do not hash raw
secrets or raw packet/log contents. The report intentionally disallows
free-text and unknown fields.

    python3 scripts/validate-split-device-evidence.py check /tmp/split-report.json
    python3 scripts/validate-split-device-evidence.py check /tmp/split-report.json --require-complete

Exit 0 means format accepted (and all rows operator-marked pass when
--require-complete is used); exit 1 means valid but incomplete/failing
under --require-complete; exit 2 means invalid. The validator does not
check that a hash corresponds to an artifact, that observations are true,
that signing is valid, or that the route is safe. A reviewer must inspect
the actual sanitized observations and confirm hashes and build identity
before closing #28. CI uses synthetic fixtures only and never generates
a physical PASS report.

## Status

NOT RUN. Neither unsigned Xcode builds, simulator XCTest, nor successful
report validation is a substitute for signed physical acceptance.

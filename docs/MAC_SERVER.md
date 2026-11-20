# Mac Mini WireGuard server deployment

This companion is a pairing UI; the macOS WireGuard server needs separate,
privileged system setup and a running agent HTTP service.

## Install

```sh
brew install wireguard-tools
# If your macOS setup requires a userspace backend, use a separately audited,
# managed Rust BoringTun CLI. It is NOT bundled into the iPhone app.
```

Use a protected configuration directory such as `/etc/wireguard` (owner root,
mode 0700). Generate keys **on the Mac**, not in a repository:

```sh
umask 077
wg genkey | tee mac-private.key | wg pubkey > mac-public.key
```

These example keys are placeholders, never real secret values:

```ini
# /etc/wireguard/wg0.conf — restrict permissions to root
[Interface]
PrivateKey = <MAC_PRIVATE_KEY>
Address = 10.8.0.1/24, fd86:ea04:1111::1/64
ListenPort = 51820

[Peer]
PublicKey = <IPHONE_PUBLIC_KEY_FROM_QR>
AllowedIPs = 10.8.0.2/32, fd86:ea04:1111::2/128
```

The actual interface name can be a dynamic `utunN` device on macOS.
Check official wireguard-tools docs for your installed variant before using
`wg-quick up wg0` and `wg show`. Use a launchd-managed, root-owned service
for reliable startup; test manually before configuring automatic restart.

## Network exposure

1. Forward **UDP 51820** from your router to the Mac Mini.
2. Publish a DDNS host pointing at your public IP.
3. Keep the agent web app reachable at **10.8.0.1:8080** *only* through the
   tunnel or another intentionally trusted local interface.
4. Configure the agent app's own authorization and CSRF protections.
5. Open the **AgentMac** companion and enter the Mac's **public** WireGuard key
   plus `your-home.ddns.net:51820`. Scan its QR with the iPhone.
6. Verify handshake from `wg show`, then load `http://10.8.0.1:8080/chat`
   after the iPhone reports VPN connected.

## Split vs full

- **Split:** iPhone routes only `10.8.0.0/24` through the tunnel. No Mac NAT
  or DNS proxy is required for Safari.
- **Full:** iPhone installs `0.0.0.0/0` and `::/0` through the tunnel,
  so the Mac must forward packets and perform suitable IPv4 NAT using `pf`
  or a correctly configured gateway. IPv6 must be **routed end-to-end** or
  separately translated; otherwise IPv6 connectivity may fail. Do not enable
  full mode until both families are tested.
- Never globally replace `pf.conf` with an untested anchor or disable macOS
  firewall. Determine the real outbound interface, scope an anchor narrowly,
  and verify recovery/reboot behavior before enabling NAT.

## End-to-end checklist

1. iOS system VPN permission granted; WireGuard tunnel shows connected.
2. `wg show` reports a recent handshake; `10.8.0.1` is reachable.
3. Agent chat streams in WKWebView; VPN-off app displays Connect VPN.
4. Split: Safari public IP remains cellular/Wi-Fi IP.
5. Full: Safari public IPv4 matches home; IPv6 works as configured.
6. iPhone lock/background and Wi-Fi → cellular transitions recover.
7. Revoke a lost device's peer on the Mac, then re-pair.

## Rust backend distinction

The iPhone PacketTunnel embeds BoringTun as a Rust static library. The
Mac Mini server is deployed/administered separately; do not install Go
as a prerequisite for the iPhone app. `wireguard-tools` supplies Mac peer
management, and an independently configured BoringTun userspace server may
be used if required by your macOS deployment. This document does not prove
that any Mac WireGuard listener is installed or running.

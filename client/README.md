# sstp-proxy

A **standalone command-line SSTP client** that turns any Microsoft **MS-SSTP**,
**SoftEther VPN Server** or public **VPN Gate** relay into a local **SOCKS5 + HTTP
proxy** — without creating a system-wide VPN, a TUN device, or requiring root.

Point your browser (or any app) at the local proxy and only that app's traffic
exits through the remote VPN server. Everything else keeps using your normal
connection.

## Why this design

* **No system-wide VPN** — the whole SSTP/PPP session and TCP/IP stack run in
  userspace (gVisor netstack). Nothing touches your OS routing table.
* **Truly standalone binaries** — pure Go, `CGO_ENABLED=0`. Cross-compiles to a
  single static executable for Windows and Linux with no mingw, no emulator, no
  DLLs and no runtime dependencies.
* **Protocol-correct** — the SSTP crypto binding (HMAC-SHA1 & HMAC-SHA256,
  PRF+/CMK/CMAC) and MS-CHAPv2 implementations are unit-tested against the
  official [MS-SSTP] and RFC 2759 test vectors, so it is compatible with
  Windows RRAS, MikroTik, SoftEther and VPN Gate.

## Features

* SSTP over TLS on **any TCP port** (not just 443) with full crypto binding.
* PPP negotiation: LCP, MS-CHAPv2 / PAP / CHAP-MD5 authentication, IPCP
  (address + DNS assignment).
* **SoftEther virtual-hub selection** via `-hub` (sent as `user@hub`).
* **SSTP echo keepalive** every 8 s so SoftEther's 20 s idle timeout never
  drops the session, plus optional `-retry` auto-reconnect.
* Local **SOCKS5** and **HTTP/HTTPS (CONNECT)** proxies.
* DNS resolved *through* the tunnel.
* IPv4 tunnelling.

## SoftEther / VPN Gate notes

* **Ports are often not 443.** SoftEther serves SSTP on the server's main TCP
  port, which VPN Gate does not list directly — decode it from the server's
  OpenVPN config (the bundled control panel does this for you) and pass
  `host:port`.
* **Self-signed certificates.** SoftEther's SSTP clone usually presents a
  self-signed cert that the native Windows client rejects; `-insecure` (on by
  default) lets you connect by IP without importing anything. This is why some
  servers only work with the SoftEther client / this tool, not Windows.
* **Virtual hubs.** Select the hub with `-hub NAME`. VPN Gate uses `vpngate`
  (usually optional there since its SSTP is bound to that hub).

## Usage

```
sstp-proxy -server HOST[:PORT] [-user U] [-pass P] [options]
```

Examples:

```
# VPN Gate relay on the standard port 443
sstp-proxy -server public-vpn-124.opengw.net -user vpn -pass vpn

# SoftEther / VPN Gate relay on a non-standard port (either form works)
sstp-proxy -server vpn258563631.opengw.net -port 1423 -user vpn -pass vpn
sstp-proxy -server vpn258563631.opengw.net:1423 -user vpn -pass vpn

# then set your browser SOCKS5 proxy to 127.0.0.1:1080
```

### Options

| Flag        | Default            | Description |
|-------------|--------------------|-------------|
| `-server`   | *(required)*       | `host`, `host:port`, or IP |
| `-port`     | `443`              | TCP port, used when `-server` has no `:port` |
| `-user`     | `vpn`              | PPP username |
| `-pass`     | `vpn`              | PPP password |
| `-hub`      | *(empty)*          | SoftEther virtual hub (auth becomes `user@hub`) |
| `-socks`    | `127.0.0.1:1080`   | SOCKS5 listen address (empty to disable) |
| `-http`     | `127.0.0.1:8080`   | HTTP proxy listen address (empty to disable) |
| `-auth`     | `auto`             | `auto` \| `mschapv2` \| `pap` |
| `-insecure` | `true`             | skip TLS cert verification (needed for VPN Gate/self-signed) |
| `-dns`      | *(empty)*          | extra DNS servers, comma separated |
| `-mtu`      | `1400`             | tunnel MTU |
| `-proxy`    | *(empty)*          | upstream proxy for reaching the server (see below) |
| `-connect`  | *(empty)*          | actual TCP endpoint to dial (domain fronting) |
| `-sni`      | *(empty)*          | TLS SNI override; `-` sends no SNI at all |
| `-host-header` | *(empty)*       | HTTP Host header override (domain fronting) |
| `-fingerprint` | *(empty)*       | mimic a browser TLS ClientHello (uTLS) |
| `-retry`    | `false`            | auto-reconnect if the tunnel drops |
| `-verbose`  | `false`            | verbose protocol logging |

## Connecting through an upstream proxy (censorship)

When a direct connection to the SSTP server is blocked but a proxy is
reachable, route the SSTP connection through it with `-proxy`:

```
# via a SOCKS5 proxy (e.g. Tor on 9050)
sstp-proxy -server vpn258563631.opengw.net:1423 -proxy socks5://127.0.0.1:9050

# via an HTTP CONNECT proxy, with authentication
sstp-proxy -server 106.158.139.230 -port 1749 -proxy http://user:pass@10.0.0.1:8080
```

Supported schemes: `http://`, `https://`, `socks5://`, `socks5h://`, each with
an optional `user:pass@` prefix. Only the outbound connection to the VPN server
goes through the upstream proxy; the local SOCKS/HTTP proxies you expose still
carry your browser traffic over the SSTP tunnel.

## Defeating DPI (SNI blocking & TLS fingerprinting)

Many censors block by inspecting the TLS ClientHello — either the SNI field or
the client's TLS fingerprint (JA3). Three independent knobs help:

```
# 1) Mimic a real browser's TLS ClientHello (uTLS). Defeats JA3 fingerprinting.
sstp-proxy -server 106.158.139.230 -port 1749 -fingerprint chrome
#   valid: chrome | firefox | safari | edge | ios | android | random

# 2) Send no SNI at all, or a custom one, to dodge SNI-based DPI.
sstp-proxy -server 106.158.139.230 -port 1749 -sni -                 # no SNI
sstp-proxy -server 106.158.139.230 -port 1749 -sni www.microsoft.com # decoy SNI

# 3) Domain fronting: connect to one endpoint but present a different SNI/Host.
sstp-proxy -server realserver.example.com \
           -connect 106.158.139.230:1749 \
           -sni cdn.bigprovider.com \
           -host-header cdn.bigprovider.com \
           -fingerprint chrome
```

These combine freely and also work together with `-proxy`. Because the server
certificate is normally self-signed, `-insecure` (default) keeps working
regardless of the SNI you present.

## Build

Requires Go 1.23+.

```
# native build
go build -o sstp-proxy .

# fully static cross builds (see build.sh for all targets)
CGO_ENABLED=0 GOOS=linux   GOARCH=amd64 go build -trimpath -ldflags "-s -w" -o dist/sstp-proxy-linux-amd64 .
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -trimpath -ldflags "-s -w" -o dist/sstp-proxy-windows-amd64.exe .
```

Or build every target at once with the helper script (it is POSIX `sh`
compatible, so any of these work):

```
sh build.sh          # or:  bash build.sh
chmod +x build.sh && ./build.sh
```

Outputs land in `dist/`.

## Tests

```
go test ./...          # unit + integration
go test -race ./...    # also race-clean
```

* `internal/ppp` verifies the SSTP crypto binding and MS-CHAPv2 against the
  published Microsoft [MS-SSTP] and RFC 2759 test vectors.
* `internal/tunnel` runs a **full end-to-end integration test**: an in-process
  mock SoftEther-style SSTP server (`internal/testserver`) and the real client
  perform the complete SSTP handshake, crypto binding, PPP LCP/MS-CHAPv2/IPCP,
  bring up both userspace netstacks, and an HTTP page is fetched **through the
  client's SOCKS5 proxy → tunnel → server**. The mock server independently
  recomputes and validates the client's crypto-binding Compound MAC.

## How it works

```
 browser ──SOCKS5/HTTP──▶ sstp-proxy ──▶ gVisor userspace TCP/IP stack
                                              │  (IP packets)
                                              ▼
                            PPP (LCP · MS-CHAPv2 · IPCP)
                                              │  (PPP frames)
                                              ▼
                         SSTP control/data over TLS (TCP/443)
                                              │
                                              ▼
                    SoftEther / Windows RRAS / VPN Gate server
```

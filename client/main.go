// sstp-proxy is a standalone command-line SSTP (MS-SSTP / SoftEther / VPN Gate)
// client that does NOT create a system-wide VPN. Instead it negotiates the SSTP
// tunnel entirely in userspace and exposes local SOCKS5 and HTTP proxies, so you
// can send just your browser's traffic through the remote VPN server.
//
// It produces fully static, dependency-free binaries for Windows and Linux via
// plain `go build` / cross-compilation (no cgo, mingw or emulators required).
package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"sstpproxy/internal/ppp"
	"sstpproxy/internal/sstp"
	"sstpproxy/internal/tunnel"
)

var version = "1.0.0"

func main() {
	var (
		server   = flag.String("server", "", "SSTP server address: host, host:port, or IP. Required.")
		port     = flag.Int("port", 443, "SSTP server TCP port (used when -server has no :port suffix). Many SoftEther/VPN Gate servers do NOT use 443.")
		user     = flag.String("user", "vpn", "PPP username (VPN Gate public relays use 'vpn')")
		pass     = flag.String("pass", "vpn", "PPP password (VPN Gate public relays use 'vpn')")
		hub      = flag.String("hub", "", "SoftEther virtual hub name. If set, the client authenticates as user@hub (VPN Gate uses 'vpngate'; usually optional there).")
		socks    = flag.String("socks", "127.0.0.1:1080", "local SOCKS5 listen address (empty to disable)")
		httpAddr = flag.String("http", "127.0.0.1:8080", "local HTTP proxy listen address (empty to disable)")
		authStr  = flag.String("auth", "auto", "PPP auth method: auto|mschapv2|pap")
		insecure = flag.Bool("insecure", true, "skip TLS certificate verification (usually required for VPN Gate/self-signed)")
		mtu      = flag.Int("mtu", 1400, "tunnel MTU")
		dnsStr   = flag.String("dns", "", "extra DNS servers, comma separated (used through the tunnel)")
		proxyURL = flag.String("proxy", "", "upstream proxy for reaching the SSTP server (useful under censorship). Formats: http://[user:pass@]host:port, https://..., socks5://[user:pass@]host:port")
		connect  = flag.String("connect", "", "actual TCP endpoint to dial host[:port] (domain fronting: dial this while presenting a different SNI/Host)")
		sni      = flag.String("sni", "", "TLS SNI to present. Use '-' to send no SNI at all. Default: derived from -server")
		hostHdr  = flag.String("host-header", "", "HTTP Host header override (domain fronting). Default: same as SNI")
		fpr      = flag.String("fingerprint", "", "mimic a browser TLS ClientHello to evade DPI: chrome|firefox|safari|edge|ios|android|random")
		retry    = flag.Bool("retry", false, "automatically reconnect if the tunnel drops")
		verbose  = flag.Bool("verbose", false, "verbose protocol logging")
		showVer  = flag.Bool("version", false, "print version and exit")
	)
	flag.Usage = usage
	flag.Parse()

	if *showVer {
		fmt.Println("sstp-proxy", version)
		return
	}
	if *server == "" {
		usage()
		os.Exit(2)
	}

	var auth ppp.AuthPref
	switch strings.ToLower(*authStr) {
	case "auto", "":
		auth = ppp.AuthAuto
	case "mschapv2", "mschap-v2", "ms-chapv2":
		auth = ppp.AuthMSCHAPv2
	case "pap":
		auth = ppp.AuthPAP
	default:
		fmt.Fprintln(os.Stderr, "invalid -auth value:", *authStr)
		os.Exit(2)
	}

	// Resolve the final server address. An explicit :port inside -server always
	// wins; otherwise the -port flag (default 443) is applied. This supports the
	// many SoftEther / VPN Gate servers that listen on non-standard ports.
	serverAddr, err := resolveServerAddr(*server, *port)
	if err != nil {
		fmt.Fprintln(os.Stderr, "invalid -server/-port:", err)
		os.Exit(2)
	}

	if *fpr != "" && !validFingerprint(*fpr) {
		fmt.Fprintf(os.Stderr, "invalid -fingerprint %q (valid: %s)\n", *fpr, strings.Join(sstp.FingerprintNames(), ", "))
		os.Exit(2)
	}

	// SoftEther selects the target virtual hub from the PPP username (user@hub).
	username := *user
	if *hub != "" && !strings.Contains(username, "@") {
		username = username + "@" + *hub
	}

	var extraDNS []net.IP
	for _, s := range strings.Split(*dnsStr, ",") {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if ip := net.ParseIP(s); ip != nil {
			extraDNS = append(extraDNS, ip)
		}
	}

	cfg := tunnel.Config{
		Server:    serverAddr,
		Username:  username,
		Password:  *pass,
		Auth:      auth,
		Insecure:  *insecure,
		SocksAddr: *socks,
		HTTPAddr:  *httpAddr,
		MTU:         *mtu,
		ExtraDNS:    extraDNS,
		Proxy:       *proxyURL,
		ConnectAddr: *connect,
		SNI:         *sni,
		HostHeader:  *hostHdr,
		Fingerprint: *fpr,
		Verbose:     *verbose,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	fmt.Println("sstp-proxy", version, "- userspace SSTP -> SOCKS/HTTP proxy")

	for {
		err := tunnel.Run(ctx, cfg)
		if ctx.Err() != nil {
			fmt.Println("[sstp] shutting down")
			return
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, "[sstp] error:", err)
			if !*retry {
				os.Exit(1)
			}
			fmt.Println("[sstp] reconnecting in 3s ...")
			select {
			case <-ctx.Done():
				return
			case <-time.After(3 * time.Second):
			}
			continue
		}
		return
	}
}

// resolveServerAddr combines the -server value with the -port flag into a final
// host:port. Rules:
//   - if -server already contains an explicit :port, that port wins;
//   - otherwise -port (default 443) is appended;
//   - bare IPv6 literals are bracketed automatically.
func resolveServerAddr(server string, port int) (string, error) {
	server = strings.TrimSpace(server)
	if server == "" {
		return "", fmt.Errorf("server is empty")
	}
	// Strip an accidental URL scheme if the user pasted one.
	for _, pfx := range []string{"https://", "http://", "sstp://"} {
		if strings.HasPrefix(strings.ToLower(server), pfx) {
			server = server[len(pfx):]
			break
		}
	}
	server = strings.TrimRight(server, "/")

	// Does it already carry a port? net.SplitHostPort succeeds for host:port
	// and for bracketed IPv6 [::1]:443.
	if host, portStr, err := net.SplitHostPort(server); err == nil {
		if p, perr := strconv.Atoi(portStr); perr == nil && p > 0 && p < 65536 {
			return net.JoinHostPort(host, portStr), nil
		}
		return "", fmt.Errorf("invalid port in server address %q", server)
	}

	if port <= 0 || port >= 65536 {
		return "", fmt.Errorf("port %d out of range", port)
	}
	// server is a bare host or IP (possibly a raw IPv6 like ::1).
	return net.JoinHostPort(server, strconv.Itoa(port)), nil
}

func validFingerprint(name string) bool {
	for _, n := range sstp.FingerprintNames() {
		if strings.EqualFold(name, n) {
			return true
		}
	}
	// "randomized-alpn" is also accepted by the sstp layer.
	return strings.EqualFold(name, "randomized-alpn")
}

func usage() {
	fmt.Fprintf(os.Stderr, `sstp-proxy %s

Connect to an MS-SSTP / SoftEther / VPN Gate server and expose local
SOCKS5 + HTTP proxies (no system-wide VPN, no TUN device, no root).

Usage:
  sstp-proxy -server HOST [-port PORT] [-user U] [-pass P] [options]

Examples:
  # VPN Gate relay on the standard port 443
  sstp-proxy -server public-vpn-124.opengw.net -user vpn -pass vpn

  # SoftEther / VPN Gate relay on a non-standard port (either form works)
  sstp-proxy -server vpn258563631.opengw.net -port 1423 -user vpn -pass vpn
  sstp-proxy -server vpn258563631.opengw.net:1423 -user vpn -pass vpn

  # then set your browser SOCKS5 proxy to 127.0.0.1:1080

  # under heavy censorship, reach the SSTP server through an upstream proxy
  sstp-proxy -server vpn258563631.opengw.net:1423 -proxy socks5://127.0.0.1:9050
  sstp-proxy -server 106.158.139.230 -port 1749 -proxy http://user:pass@10.0.0.1:8080

  # DPI evasion: mimic a Chrome TLS ClientHello
  sstp-proxy -server 106.158.139.230 -port 1749 -fingerprint chrome

  # send no SNI at all (defeat SNI-based DPI blocking)
  sstp-proxy -server 106.158.139.230 -port 1749 -sni -

  # domain fronting: dial one address, present a different SNI/Host
  sstp-proxy -server realserver.example.com -connect 106.158.139.230:1749 \
             -sni cdn.bigprovider.com -fingerprint chrome

Options:
`, version)
	flag.PrintDefaults()
}

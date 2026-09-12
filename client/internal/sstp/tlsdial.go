package sstp

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	utls "github.com/refraction-networking/utls"
)

// handshakeTLS performs the TLS handshake over raw, either with the standard Go
// TLS stack or, when a fingerprint is requested, with uTLS so the ClientHello
// mimics a real browser and defeats DPI TLS-fingerprint blocking. It returns
// the established connection and the server leaf certificate (DER).
func handshakeTLS(raw net.Conn, sni string, insecure bool, fingerprint string, timeout time.Duration) (net.Conn, []byte, error) {
	raw.SetDeadline(time.Now().Add(timeout))
	defer raw.SetDeadline(time.Time{})

	if strings.TrimSpace(fingerprint) == "" {
		// Standard Go TLS stack.
		cfg := &tls.Config{
			ServerName:         sni,
			InsecureSkipVerify: insecure,
			MinVersion:         tls.VersionTLS12,
		}
		tc := tls.Client(raw, cfg)
		if err := tc.Handshake(); err != nil {
			return nil, nil, fmt.Errorf("tls handshake: %w", err)
		}
		st := tc.ConnectionState()
		if len(st.PeerCertificates) == 0 {
			tc.Close()
			return nil, nil, errors.New("server presented no certificate")
		}
		return tc, st.PeerCertificates[0].Raw, nil
	}

	// uTLS path: mimic a real browser ClientHello.
	hello, err := helloID(fingerprint)
	if err != nil {
		return nil, nil, err
	}
	cfg := &utls.Config{
		ServerName:         sni,
		InsecureSkipVerify: insecure,
		MinVersion:         utls.VersionTLS12,
	}
	uc := utls.UClient(raw, cfg, hello)
	if err := uc.Handshake(); err != nil {
		return nil, nil, fmt.Errorf("utls handshake (%s): %w", fingerprint, err)
	}
	st := uc.ConnectionState()
	if len(st.PeerCertificates) == 0 {
		uc.Close()
		return nil, nil, errors.New("server presented no certificate")
	}
	// Extract DER; PeerCertificates are *x509.Certificate.
	var leaf []byte
	if c, ok := any(st.PeerCertificates[0]).(*x509.Certificate); ok {
		leaf = c.Raw
	} else {
		leaf = st.PeerCertificates[0].Raw
	}
	return uc, leaf, nil
}

// helloID maps a friendly fingerprint name to a uTLS ClientHelloID.
func helloID(name string) (utls.ClientHelloID, error) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "chrome", "chrome-latest":
		return utls.HelloChrome_Auto, nil
	case "firefox", "ff":
		return utls.HelloFirefox_Auto, nil
	case "safari":
		return utls.HelloSafari_Auto, nil
	case "edge":
		return utls.HelloEdge_Auto, nil
	case "ios":
		return utls.HelloIOS_Auto, nil
	case "android":
		return utls.HelloAndroid_11_OkHttp, nil
	case "random", "rand":
		return utls.HelloRandomized, nil
	case "randomized-alpn":
		return utls.HelloRandomizedALPN, nil
	default:
		return utls.ClientHelloID{}, fmt.Errorf("unknown TLS fingerprint %q (use chrome, firefox, safari, edge, ios, android or random)", name)
	}
}

// FingerprintNames returns the accepted -fingerprint values, for help text.
func FingerprintNames() []string {
	return []string{"chrome", "firefox", "safari", "edge", "ios", "android", "random"}
}

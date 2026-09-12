package tunnel

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"sstpproxy/internal/ppp"
	"sstpproxy/internal/testserver"
)

// TestEndToEnd spins up a mock SoftEther-style SSTP server and the real client,
// then fetches an HTTP page through the client's SOCKS5 proxy. It exercises the
// whole pipeline: SSTP handshake, crypto binding, PPP LCP/MS-CHAPv2/IPCP, the
// userspace netstack, packet pumping in both directions, and the SOCKS proxy.
func TestEndToEnd(t *testing.T) {
	srv, err := testserver.New("secret-pass")
	if err != nil {
		t.Fatalf("start test server: %v", err)
	}
	defer srv.Close()

	socksAddr := "127.0.0.1:38099"
	cfg := Config{
		Server:    srv.Addr,
		Username:  "tester",
		Password:  "secret-pass",
		Auth:      ppp.AuthMSCHAPv2,
		Insecure:  true,
		SocksAddr: socksAddr,
		HTTPAddr:  "",
		MTU:       1400,
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	runErr := make(chan error, 1)
	go func() { runErr <- Run(ctx, cfg) }()

	// Wait for the SOCKS proxy to come up (only starts once the tunnel is up).
	if !waitPort(socksAddr, 15*time.Second) {
		select {
		case err := <-runErr:
			t.Fatalf("tunnel exited before SOCKS came up: %v", err)
		default:
		}
		t.Fatal("SOCKS proxy did not start in time")
	}

	// Fetch through the SOCKS proxy -> tunnel -> server netstack HTTP origin.
	target := net.JoinHostPort(srv.ServerIP(), "80")
	var body string
	var lastErr error
	for i := 0; i < 20; i++ {
		body, lastErr = socksGet(socksAddr, target)
		if lastErr == nil {
			break
		}
		time.Sleep(300 * time.Millisecond)
	}
	if lastErr != nil {
		t.Fatalf("HTTP over SOCKS failed: %v", lastErr)
	}
	if !strings.Contains(body, "hello-through-sstp-tunnel") {
		t.Fatalf("unexpected body via tunnel: %q", body)
	}
	t.Log("HTTP fetch through SSTP tunnel + SOCKS proxy succeeded")

	// Crypto binding must have validated on the server side.
	ok, cerr := srv.CryptoBindingValidated()
	if !ok {
		t.Fatalf("server did not validate crypto binding: %s", cerr)
	}
	t.Log("server validated the client's crypto-binding Compound MAC")
}

func waitPort(addr string, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp", addr, time.Second)
		if err == nil {
			c.Close()
			return true
		}
		time.Sleep(200 * time.Millisecond)
	}
	return false
}

// socksGet performs a minimal SOCKS5 CONNECT then an HTTP/1.0 GET.
func socksGet(socksAddr, target string) (string, error) {
	c, err := net.DialTimeout("tcp", socksAddr, 5*time.Second)
	if err != nil {
		return "", err
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(10 * time.Second))

	// greeting: no-auth
	if _, err := c.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		return "", err
	}
	resp := make([]byte, 2)
	if _, err := io.ReadFull(c, resp); err != nil {
		return "", err
	}
	if resp[0] != 0x05 || resp[1] != 0x00 {
		return "", fmt.Errorf("socks greeting rejected: %v", resp)
	}

	host, portStr, _ := net.SplitHostPort(target)
	port, _ := strconv.Atoi(portStr)
	ip := net.ParseIP(host).To4()
	if ip == nil {
		return "", fmt.Errorf("expected IPv4 target")
	}
	req := []byte{0x05, 0x01, 0x00, 0x01}
	req = append(req, ip...)
	pb := make([]byte, 2)
	binary.BigEndian.PutUint16(pb, uint16(port))
	req = append(req, pb...)
	if _, err := c.Write(req); err != nil {
		return "", err
	}
	rep := make([]byte, 10)
	if _, err := io.ReadFull(c, rep); err != nil {
		return "", err
	}
	if rep[1] != 0x00 {
		return "", fmt.Errorf("socks connect failed, code=%d", rep[1])
	}

	// HTTP/1.0 request over the established tunnel.
	fmt.Fprintf(c, "GET / HTTP/1.0\r\nHost: %s\r\n\r\n", host)
	data, err := io.ReadAll(c)
	if err != nil && len(data) == 0 {
		return "", err
	}
	return string(data), nil
}

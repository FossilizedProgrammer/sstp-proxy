// Package upstream provides dialers that route the outbound TCP connection to
// the SSTP server through an upstream proxy. This is useful under heavy
// censorship, where a direct connection to the VPN server is blocked but an
// HTTP(S) or SOCKS proxy is reachable.
//
// Supported proxy URL schemes:
//
//	http://[user:pass@]host:port    HTTP CONNECT proxy
//	https://[user:pass@]host:port   HTTP CONNECT proxy over TLS
//	socks5://[user:pass@]host:port  SOCKS5 proxy (remote DNS)
//	socks5h://[user:pass@]host:port alias for socks5
package upstream

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/net/proxy"
)

// DialFunc dials a TCP connection to addr ("host:port"), possibly via a proxy.
type DialFunc func(ctx context.Context, network, addr string) (net.Conn, error)

// Direct returns a plain dialer that connects straight to the target.
func Direct(timeout time.Duration) DialFunc {
	d := &net.Dialer{Timeout: timeout}
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		return d.DialContext(ctx, network, addr)
	}
}

// FromURL builds a DialFunc from a proxy URL. An empty proxyURL returns a
// direct dialer.
func FromURL(proxyURL string, timeout time.Duration) (DialFunc, error) {
	proxyURL = strings.TrimSpace(proxyURL)
	if proxyURL == "" {
		return Direct(timeout), nil
	}
	u, err := url.Parse(proxyURL)
	if err != nil {
		return nil, fmt.Errorf("invalid proxy URL %q: %w", proxyURL, err)
	}
	switch strings.ToLower(u.Scheme) {
	case "socks5", "socks5h":
		return socks5Dialer(u, timeout)
	case "http", "https":
		return httpConnectDialer(u, timeout), nil
	default:
		return nil, fmt.Errorf("unsupported proxy scheme %q (use http, https, socks5 or socks5h)", u.Scheme)
	}
}

func socks5Dialer(u *url.URL, timeout time.Duration) (DialFunc, error) {
	var auth *proxy.Auth
	if u.User != nil {
		pass, _ := u.User.Password()
		auth = &proxy.Auth{User: u.User.Username(), Password: pass}
	}
	base := &net.Dialer{Timeout: timeout}
	d, err := proxy.SOCKS5("tcp", u.Host, auth, base)
	if err != nil {
		return nil, fmt.Errorf("socks5 proxy: %w", err)
	}
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		if cd, ok := d.(proxy.ContextDialer); ok {
			return cd.DialContext(ctx, network, addr)
		}
		return d.Dial(network, addr)
	}, nil
}

func httpConnectDialer(u *url.URL, timeout time.Duration) DialFunc {
	useTLS := strings.EqualFold(u.Scheme, "https")
	proxyHost := u.Host
	if _, _, err := net.SplitHostPort(proxyHost); err != nil {
		if useTLS {
			proxyHost = net.JoinHostPort(proxyHost, "443")
		} else {
			proxyHost = net.JoinHostPort(proxyHost, "8080")
		}
	}
	var authHeader string
	if u.User != nil {
		pass, _ := u.User.Password()
		creds := u.User.Username() + ":" + pass
		authHeader = "Basic " + base64.StdEncoding.EncodeToString([]byte(creds))
	}

	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		base := &net.Dialer{Timeout: timeout}
		conn, err := base.DialContext(ctx, "tcp", proxyHost)
		if err != nil {
			return nil, fmt.Errorf("connect to proxy %s: %w", proxyHost, err)
		}
		if useTLS {
			host, _, _ := net.SplitHostPort(proxyHost)
			tconn := tls.Client(conn, &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12})
			if err := tconn.HandshakeContext(ctx); err != nil {
				conn.Close()
				return nil, fmt.Errorf("proxy TLS handshake: %w", err)
			}
			conn = tconn
		}

		// Send the CONNECT request.
		req := &http.Request{
			Method: http.MethodConnect,
			URL:    &url.URL{Opaque: addr},
			Host:   addr,
			Header: make(http.Header),
		}
		req.Header.Set("Proxy-Connection", "Keep-Alive")
		req.Header.Set("User-Agent", "Mozilla/5.0")
		if authHeader != "" {
			req.Header.Set("Proxy-Authorization", authHeader)
		}
		if err := req.Write(conn); err != nil {
			conn.Close()
			return nil, fmt.Errorf("write CONNECT: %w", err)
		}

		br := bufio.NewReader(conn)
		resp, err := http.ReadResponse(br, req)
		if err != nil {
			conn.Close()
			return nil, fmt.Errorf("read CONNECT response: %w", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			conn.Close()
			return nil, fmt.Errorf("proxy CONNECT failed: %s", resp.Status)
		}
		// If the proxy buffered extra bytes past the header, wrap the conn.
		if br.Buffered() > 0 {
			return &bufferedConn{Conn: conn, r: br}, nil
		}
		return conn, nil
	}
}

// bufferedConn preserves any bytes the proxy sent immediately after the CONNECT
// response headers so the TLS handshake that follows does not lose them.
type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) { return c.r.Read(p) }

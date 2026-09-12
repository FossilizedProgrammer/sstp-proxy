// Package proxy exposes local SOCKS5 and HTTP proxy servers that forward every
// connection through a user-supplied Dialer (the SSTP tunnel). Only the browser
// (or any app configured to use the proxy) is affected — routing stays local.
package proxy

import (
	"bufio"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"time"
)

// Dialer originates outbound TCP connections (through the tunnel).
type Dialer interface {
	DialContext(ctx context.Context, network, addr string) (net.Conn, error)
}

// Logf is a simple logging callback.
type Logf func(format string, args ...any)

// pipe copies data bidirectionally between a and b until either side closes.
func pipe(a, b net.Conn) {
	done := make(chan struct{}, 2)
	cp := func(dst, src net.Conn) {
		_, _ = io.Copy(dst, src)
		if tc, ok := dst.(interface{ CloseWrite() error }); ok {
			_ = tc.CloseWrite()
		}
		done <- struct{}{}
	}
	go cp(a, b)
	go cp(b, a)
	<-done
	<-done
	a.Close()
	b.Close()
}

// ---------------- SOCKS5 ----------------

// ServeSOCKS runs a SOCKS5 server on ln, dialing upstreams via d.
func ServeSOCKS(ln net.Listener, d Dialer, log Logf) error {
	for {
		c, err := ln.Accept()
		if err != nil {
			return err
		}
		go handleSOCKS(c, d, log)
	}
}

func handleSOCKS(c net.Conn, d Dialer, log Logf) {
	defer c.Close()
	c.SetDeadline(time.Now().Add(30 * time.Second))
	br := bufio.NewReader(c)

	// Greeting: VER, NMETHODS, METHODS...
	ver, err := br.ReadByte()
	if err != nil || ver != 0x05 {
		return
	}
	nmethods, err := br.ReadByte()
	if err != nil {
		return
	}
	if _, err := io.CopyN(io.Discard, br, int64(nmethods)); err != nil {
		return
	}
	// Reply: no authentication required.
	if _, err := c.Write([]byte{0x05, 0x00}); err != nil {
		return
	}

	// Request: VER, CMD, RSV, ATYP, ADDR, PORT
	hdr := make([]byte, 4)
	if _, err := io.ReadFull(br, hdr); err != nil {
		return
	}
	if hdr[0] != 0x05 {
		return
	}
	cmd, atyp := hdr[1], hdr[3]

	var host string
	switch atyp {
	case 0x01: // IPv4
		b := make([]byte, 4)
		if _, err := io.ReadFull(br, b); err != nil {
			return
		}
		host = net.IP(b).String()
	case 0x03: // domain
		l, err := br.ReadByte()
		if err != nil {
			return
		}
		b := make([]byte, int(l))
		if _, err := io.ReadFull(br, b); err != nil {
			return
		}
		host = string(b)
	case 0x04: // IPv6
		b := make([]byte, 16)
		if _, err := io.ReadFull(br, b); err != nil {
			return
		}
		host = net.IP(b).String()
	default:
		socksReply(c, 0x08)
		return
	}
	var pb [2]byte
	if _, err := io.ReadFull(br, pb[:]); err != nil {
		return
	}
	port := binary.BigEndian.Uint16(pb[:])
	target := net.JoinHostPort(host, strconv.Itoa(int(port)))

	if cmd != 0x01 { // only CONNECT
		socksReply(c, 0x07)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	up, err := d.DialContext(ctx, "tcp", target)
	if err != nil {
		if log != nil {
			log("socks: dial %s failed: %v", target, err)
		}
		socksReply(c, 0x05) // connection refused
		return
	}
	socksReply(c, 0x00)
	c.SetDeadline(time.Time{})
	if log != nil {
		log("socks: %s connected", target)
	}
	pipe(c, up)
}

func socksReply(c net.Conn, code byte) {
	// VER, REP, RSV, ATYP=IPv4, BND.ADDR=0, BND.PORT=0
	_, _ = c.Write([]byte{0x05, code, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
}

// ---------------- HTTP proxy ----------------

// ServeHTTP runs an HTTP/HTTPS proxy on ln, dialing upstreams via d.
func ServeHTTP(ln net.Listener, d Dialer, log Logf) error {
	handler := &httpProxy{d: d, log: log}
	srv := &http.Server{Handler: handler}
	return srv.Serve(ln)
}

type httpProxy struct {
	d   Dialer
	log Logf
}

func (h *httpProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		h.handleConnect(w, r)
		return
	}
	h.handlePlain(w, r)
}

func (h *httpProxy) handleConnect(w http.ResponseWriter, r *http.Request) {
	target := r.Host
	if _, _, err := net.SplitHostPort(target); err != nil {
		target = net.JoinHostPort(target, "443")
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	up, err := h.d.DialContext(ctx, "tcp", target)
	if err != nil {
		http.Error(w, "upstream dial failed: "+err.Error(), http.StatusBadGateway)
		return
	}
	hj, ok := w.(http.Hijacker)
	if !ok {
		up.Close()
		http.Error(w, "hijacking not supported", http.StatusInternalServerError)
		return
	}
	client, _, err := hj.Hijack()
	if err != nil {
		up.Close()
		return
	}
	_, _ = client.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
	if h.log != nil {
		h.log("http: CONNECT %s", target)
	}
	pipe(client, up)
}

func (h *httpProxy) handlePlain(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Host
	if host == "" {
		host = r.Host
	}
	if host == "" {
		http.Error(w, "missing host", http.StatusBadRequest)
		return
	}
	if _, _, err := net.SplitHostPort(host); err != nil {
		host = net.JoinHostPort(host, "80")
	}
	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()
	up, err := h.d.DialContext(ctx, "tcp", host)
	if err != nil {
		http.Error(w, "upstream dial failed: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer up.Close()

	r.RequestURI = ""
	r.URL.Scheme = ""
	r.URL.Host = ""
	// Strip hop-by-hop headers.
	r.Header.Del("Proxy-Connection")
	r.Header.Del("Proxy-Authenticate")
	r.Header.Del("Proxy-Authorization")

	if err := r.Write(up); err != nil {
		http.Error(w, "write upstream failed: "+err.Error(), http.StatusBadGateway)
		return
	}
	resp, err := http.ReadResponse(bufio.NewReader(up), r)
	if err != nil {
		http.Error(w, "read upstream failed: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	for k, vv := range resp.Header {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
	if h.log != nil {
		h.log("http: %s %s -> %d", r.Method, host, resp.StatusCode)
	}
}

// StatusString gives a short human-readable proxy address summary.
func StatusString(socks, http string) string {
	return fmt.Sprintf("SOCKS5 %s | HTTP %s", socks, http)
}

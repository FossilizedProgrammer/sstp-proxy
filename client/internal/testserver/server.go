// Package testserver implements a minimal SSTP + PPP server that mimics the
// behaviour of a SoftEther VPN Server's MS-SSTP clone. It is used by the
// integration test to exercise the full client pipeline (SSTP handshake,
// crypto binding, PPP LCP/MS-CHAPv2/IPCP, userspace netstack and the SOCKS/HTTP
// proxies) over a TLS loopback — no external server required.
//
// It is deliberately NOT imported by the main binary; it exists for testing.
package testserver

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"

	"sstpproxy/internal/ppp"
	"sstpproxy/internal/sstp"

	"golang.zx2c4.com/wireguard/tun/netstack"
)

// PPP constants (subset) — reimplemented here so the server is an independent
// implementation of the wire format.
const (
	pppLCP  = 0xC021
	pppCHAP = 0xC223
	pppIPCP = 0x8021
	pppIP   = 0x0021

	cfgReq = 1
	cfgAck = 2
	cfgNak = 3
	cfgRej = 4
	echoReq = 9
	echoRep = 10

	chapChallenge = 1
	chapResponse  = 2
	chapSuccess   = 3

	algoMSCHAPv2 = 0x81
)

// Server is a running mock SSTP endpoint.
type Server struct {
	Addr     string // host:port the server listens on
	Password string // expected account password (for CMAC validation)

	// Assigned tunnel addressing.
	clientIP net.IP // address handed to the client
	serverIP net.IP // gateway / target address owned by the server netstack
	dns      net.IP

	ln       net.Listener
	tlsCfg   *tls.Config
	certDER  []byte

	// server-side userspace network (acts as tunnel peer + HTTP origin)
	sn    *netstack.Net
	sdev  interface {
		Read(bufs [][]byte, sizes []int, offset int) (int, error)
		Write(bufs [][]byte, offset int) (int, error)
		Close() error
	}

	writeMu sync.Mutex

	// results captured for assertions
	mu             sync.Mutex
	cryptoValidated bool
	cryptoErr       string

	closeOnce sync.Once
	closed    chan struct{}
}

// New starts a mock SSTP server on 127.0.0.1 with an ephemeral port. It also
// stands up a server-side netstack that owns serverIP and serves a small HTTP
// origin on serverIP:80, so traffic tunnelled by the client can complete.
func New(password string) (*Server, error) {
	s := &Server{
		Password: password,
		clientIP: net.IPv4(192, 168, 77, 2),
		serverIP: net.IPv4(192, 168, 77, 1),
		dns:      net.IPv4(192, 168, 77, 1),
		closed:   make(chan struct{}),
	}

	cert, der, err := selfSignedCert()
	if err != nil {
		return nil, err
	}
	s.certDER = der
	s.tlsCfg = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}

	// Server-side netstack owning the gateway/target IP.
	srvAddr, _ := netip.AddrFromSlice(s.serverIP.To4())
	dev, sn, err := netstack.CreateNetTUN(
		[]netip.Addr{srvAddr},
		[]netip.Addr{srvAddr},
		1400,
	)
	if err != nil {
		return nil, err
	}
	s.sdev = dev
	s.sn = sn

	// HTTP origin reachable through the tunnel at serverIP:80.
	httpLn, err := sn.ListenTCP(&net.TCPAddr{IP: s.serverIP, Port: 80})
	if err != nil {
		dev.Close()
		return nil, err
	}
	go http.Serve(httpLn, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		io.WriteString(w, "hello-through-sstp-tunnel")
	}))

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		dev.Close()
		return nil, err
	}
	s.ln = ln
	s.Addr = ln.Addr().String()

	go s.acceptLoop()
	return s, nil
}

// ServerIP is the in-tunnel address of the HTTP origin (dial serverIP:80).
func (s *Server) ServerIP() string { return s.serverIP.String() }

// CryptoBindingValidated reports whether the client's crypto-binding Compound
// MAC matched the value recomputed by the server.
func (s *Server) CryptoBindingValidated() (bool, string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.cryptoValidated, s.cryptoErr
}

// Close shuts the server down. It closes the TCP listener but, like the client,
// deliberately does not close the userspace netstack device to avoid the
// wireguard-go netstack Close()/timer-write shutdown race; the netstack holds no
// OS resources and is reclaimed at process exit.
func (s *Server) Close() {
	s.closeOnce.Do(func() {
		close(s.closed)
		s.ln.Close()
	})
}

func (s *Server) acceptLoop() {
	for {
		c, err := s.ln.Accept()
		if err != nil {
			return
		}
		go s.handle(c)
	}
}

type conn struct {
	tc  *tls.Conn
	br  *bufio.Reader
	srv *Server

	// PPP state
	nonce       []byte
	ntResponse  []byte
	lcpPeer     bool
	lcpOurs     bool
	ipcpPeer    bool
	ipcpOurs    bool
	pumpStarted bool
}

func (s *Server) handle(raw net.Conn) {
	defer raw.Close()
	tc := tls.Server(raw, s.tlsCfg)
	if err := tc.Handshake(); err != nil {
		return
	}
	c := &conn{tc: tc, br: bufio.NewReaderSize(tc, 65536), srv: s}

	if err := c.httpHandshake(); err != nil {
		return
	}

	for {
		control, msgType, attrs, data, rawpkt, err := c.readSSTP()
		if err != nil {
			return
		}
		if control {
			c.handleControl(msgType, attrs, rawpkt)
		} else {
			c.handlePPP(data)
		}
	}
}

func (c *conn) httpHandshake() error {
	// Read request line + headers up to blank line.
	line, err := c.br.ReadString('\n')
	if err != nil {
		return err
	}
	if !strings.HasPrefix(line, "SSTP_DUPLEX_POST") {
		return errors.New("unexpected SSTP request line")
	}
	for {
		h, err := c.br.ReadString('\n')
		if err != nil {
			return err
		}
		if strings.TrimSpace(h) == "" {
			break
		}
	}
	// SoftEther-style response.
	resp := "HTTP/1.1 200 OK\r\n" +
		"Content-Length: 18446744073709551615\r\n" +
		"Server: Microsoft-HTTPAPI/2.0\r\n" +
		"\r\n"
	_, err = io.WriteString(c.tc, resp)
	return err
}

// readSSTP parses one SSTP packet from the wire.
func (c *conn) readSSTP() (control bool, msgType uint16, attrs []sstp.Attr, data []byte, raw []byte, err error) {
	var hdr [4]byte
	if _, err = io.ReadFull(c.br, hdr[:]); err != nil {
		return
	}
	if hdr[0] != sstp.Version {
		err = fmt.Errorf("bad version 0x%02x", hdr[0])
		return
	}
	length := int(binary.BigEndian.Uint16(hdr[2:4]) & 0x0FFF)
	if length < 4 {
		err = errors.New("short packet")
		return
	}
	body := make([]byte, length-4)
	if _, err = io.ReadFull(c.br, body); err != nil {
		return
	}
	raw = append(append([]byte{}, hdr[:]...), body...)
	control = hdr[1]&0x01 != 0
	if !control {
		data = body
		return
	}
	if len(body) < 4 {
		err = errors.New("short control")
		return
	}
	msgType = binary.BigEndian.Uint16(body[0:2])
	num := int(binary.BigEndian.Uint16(body[2:4]))
	off := 4
	for i := 0; i < num; i++ {
		if off+4 > len(body) {
			break
		}
		id := body[off+1]
		alen := int(binary.BigEndian.Uint16(body[off+2:off+4]) & 0x0FFF)
		if alen < 4 || off+alen > len(body) {
			break
		}
		attrs = append(attrs, sstp.Attr{ID: id, Value: body[off+4 : off+alen]})
		off += alen
	}
	return
}

func (c *conn) write(b []byte) error {
	c.srv.writeMu.Lock()
	defer c.srv.writeMu.Unlock()
	_, err := c.tc.Write(b)
	return err
}

func (c *conn) sendData(ppp []byte) error {
	buf := make([]byte, 4+len(ppp))
	buf[0] = sstp.Version
	buf[1] = 0x00
	binary.BigEndian.PutUint16(buf[2:4], uint16(4+len(ppp)))
	copy(buf[4:], ppp)
	return c.write(buf)
}

func (c *conn) handleControl(msgType uint16, attrs []sstp.Attr, raw []byte) {
	switch msgType {
	case sstp.MsgCallConnectRequest:
		c.nonce = make([]byte, 32)
		_, _ = rand.Read(c.nonce)
		// value: reserved(3) + bitmask(1) + nonce(32)
		val := make([]byte, 36)
		val[3] = sstp.CertHashProtocolSHA256
		copy(val[4:], c.nonce)
		attr := sstp.BuildAttr(sstp.AttrCryptoBindingReq, val)
		_ = c.write(sstp.BuildControl(sstp.MsgCallConnectAck, attr, 1))
		// Begin PPP: send our LCP Configure-Request (auth = MS-CHAPv2).
		c.sendLCPReq()
	case sstp.MsgCallConnected:
		c.validateCrypto(attrs, raw)
	case sstp.MsgEchoRequest:
		_ = c.write(sstp.BuildControl(sstp.MsgEchoResponse, nil, 0))
	}
}

func (c *conn) validateCrypto(attrs []sstp.Attr, raw []byte) {
	for _, a := range attrs {
		if a.ID != sstp.AttrCryptoBinding || len(a.Value) < 100 {
			continue
		}
		// value layout: reserved(3)+bitmask(1)+nonce(32)+certHash(32)+mac(32)
		clientMAC := append([]byte{}, a.Value[68:100]...)
		hlak := ppp.ServerComputeClientHLAK(c.srv.Password, c.ntResponse)
		cmk := ppp.ComputeCMK(hlak, true)
		// Zero the MAC field inside the raw message (offset 8+4+68 = 80).
		zeroed := append([]byte{}, raw...)
		for i := 80; i < 112 && i < len(zeroed); i++ {
			zeroed[i] = 0
		}
		expect := ppp.ComputeCMAC(cmk, zeroed, true)
		ok := len(expect) == len(clientMAC)
		if ok {
			for i := range expect {
				if expect[i] != clientMAC[i] {
					ok = false
					break
				}
			}
		}
		c.srv.mu.Lock()
		c.srv.cryptoValidated = ok
		if !ok {
			c.srv.cryptoErr = "compound MAC mismatch"
		}
		c.srv.mu.Unlock()
		return
	}
	c.srv.mu.Lock()
	c.srv.cryptoErr = "no crypto binding attribute"
	c.srv.mu.Unlock()
}

// ---- PPP ----

func pppEncode(proto uint16, payload []byte) []byte {
	out := make([]byte, 4+len(payload))
	out[0] = 0xFF
	out[1] = 0x03
	binary.BigEndian.PutUint16(out[2:4], proto)
	copy(out[4:], payload)
	return out
}

func pppDecode(frame []byte) (uint16, []byte, bool) {
	i := 0
	if len(frame) >= 2 && frame[0] == 0xFF && frame[1] == 0x03 {
		i = 2
	}
	if len(frame) < i+1 {
		return 0, nil, false
	}
	var proto uint16
	if frame[i]&0x01 == 1 {
		proto = uint16(frame[i])
		i++
	} else {
		if len(frame) < i+2 {
			return 0, nil, false
		}
		proto = binary.BigEndian.Uint16(frame[i : i+2])
		i += 2
	}
	return proto, frame[i:], true
}

func ctrl(code, id byte, data []byte) []byte {
	out := make([]byte, 4+len(data))
	out[0] = code
	out[1] = id
	binary.BigEndian.PutUint16(out[2:4], uint16(4+len(data)))
	copy(out[4:], data)
	return out
}

func (c *conn) sendLCPReq() {
	// MRU + Magic + Auth(CHAP/MS-CHAPv2)
	var opts []byte
	opts = append(opts, 1, 4, 0x05, 0xDC) // MRU 1500
	opts = append(opts, 5, 6, 0xDE, 0xAD, 0xBE, 0xEF) // Magic
	opts = append(opts, 3, 5, 0xC2, 0x23, algoMSCHAPv2) // Auth
	_ = c.sendData(pppEncode(pppLCP, ctrl(cfgReq, 1, opts)))
}

func (c *conn) handlePPP(frame []byte) {
	proto, payload, ok := pppDecode(frame)
	if !ok || len(payload) < 4 {
		return
	}
	switch proto {
	case pppLCP:
		c.handleLCP(payload)
	case pppCHAP:
		c.handleCHAP(payload)
	case pppIPCP:
		c.handleIPCP(payload)
	case pppIP:
		// Inject the client's IP packet into the server netstack.
		buf := make([]byte, len(payload))
		copy(buf, payload)
		_, _ = c.srv.sdev.Write([][]byte{buf}, 0)
	}
}

func (c *conn) handleLCP(p []byte) {
	code, id := p[0], p[1]
	length := int(binary.BigEndian.Uint16(p[2:4]))
	if length > len(p) {
		length = len(p)
	}
	data := p[4:length]
	switch code {
	case cfgReq:
		// Accept the client's options verbatim.
		_ = c.sendData(pppEncode(pppLCP, ctrl(cfgAck, id, data)))
		c.lcpPeer = true
		c.maybeChallenge()
	case cfgAck:
		c.lcpOurs = true
		c.maybeChallenge()
	case cfgNak, cfgRej:
		// Retry with only magic to keep it simple.
		opts := []byte{5, 6, 0xDE, 0xAD, 0xBE, 0xEF}
		_ = c.sendData(pppEncode(pppLCP, ctrl(cfgReq, id+1, opts)))
	case echoReq:
		_ = c.sendData(pppEncode(pppLCP, ctrl(echoRep, id, []byte{0xDE, 0xAD, 0xBE, 0xEF})))
	}
}

func (c *conn) maybeChallenge() {
	if c.lcpPeer && c.lcpOurs && c.nonce != nil && c.ntResponse == nil {
		// Send an MS-CHAPv2 challenge (16-byte value).
		chal := make([]byte, 16)
		_, _ = rand.Read(chal)
		data := append([]byte{16}, chal...)
		data = append(data, []byte("sstp-test-server")...)
		_ = c.sendData(pppEncode(pppCHAP, ctrl(chapChallenge, 1, data)))
	}
}

func (c *conn) handleCHAP(p []byte) {
	code, id := p[0], p[1]
	length := int(binary.BigEndian.Uint16(p[2:4]))
	if length > len(p) {
		length = len(p)
	}
	data := p[4:length]
	if code == chapResponse && len(data) >= 1 {
		vs := int(data[0])
		if 1+vs <= len(data) && vs >= 49 {
			val := data[1 : 1+vs]
			c.ntResponse = append([]byte{}, val[24:48]...)
		}
		_ = c.sendData(pppEncode(pppCHAP, ctrl(chapSuccess, id, []byte("S=OK"))))
		// Advertise our own IPCP config request.
		c.sendIPCPReq()
	}
}

func ipcpOpt(t byte, v []byte) []byte {
	out := make([]byte, 2+len(v))
	out[0] = t
	out[1] = byte(2 + len(v))
	copy(out[2:], v)
	return out
}

func (c *conn) sendIPCPReq() {
	opts := ipcpOpt(3, c.srv.serverIP.To4())
	_ = c.sendData(pppEncode(pppIPCP, ctrl(cfgReq, 1, opts)))
}

func (c *conn) handleIPCP(p []byte) {
	code, id := p[0], p[1]
	length := int(binary.BigEndian.Uint16(p[2:4]))
	if length > len(p) {
		length = len(p)
	}
	data := p[4:length]
	switch code {
	case cfgReq:
		// Inspect the client's requested IP; Nak until it matches assigned.
		clientIP, priDNS := extractIPCP(data)
		if clientIP.Equal(c.srv.clientIP) && priDNS.Equal(c.srv.dns) {
			_ = c.sendData(pppEncode(pppIPCP, ctrl(cfgAck, id, data)))
			c.ipcpPeer = true
			c.maybeUp()
		} else {
			var nak []byte
			nak = append(nak, ipcpOpt(3, c.srv.clientIP.To4())...)
			nak = append(nak, ipcpOpt(129, c.srv.dns.To4())...)
			nak = append(nak, ipcpOpt(131, c.srv.dns.To4())...)
			_ = c.sendData(pppEncode(pppIPCP, ctrl(cfgNak, id, nak)))
		}
	case cfgAck:
		c.ipcpOurs = true
		c.maybeUp()
	case cfgNak:
		// Client should re-request; nothing to do.
	}
}

func extractIPCP(opts []byte) (ip net.IP, priDNS net.IP) {
	ip = net.IPv4zero
	priDNS = net.IPv4zero
	i := 0
	for i+2 <= len(opts) {
		t := opts[i]
		l := int(opts[i+1])
		if l < 2 || i+l > len(opts) {
			break
		}
		v := opts[i+2 : i+l]
		switch t {
		case 3:
			if len(v) == 4 {
				ip = net.IPv4(v[0], v[1], v[2], v[3])
			}
		case 129:
			if len(v) == 4 {
				priDNS = net.IPv4(v[0], v[1], v[2], v[3])
			}
		}
		i += l
	}
	return
}

func (c *conn) maybeUp() {
	if c.ipcpPeer && c.ipcpOurs && !c.pumpStarted {
		c.pumpStarted = true
		go c.outboundPump()
	}
}

// outboundPump moves packets produced by the server netstack (e.g. TCP
// SYN-ACKs and HTTP responses) back to the client over the tunnel.
func (c *conn) outboundPump() {
	for {
		select {
		case <-c.srv.closed:
			return
		default:
		}
		bufs := [][]byte{make([]byte, 1600)}
		sizes := make([]int, 1)
		n, err := c.srv.sdev.Read(bufs, sizes, 0)
		if err != nil {
			return
		}
		if n == 0 || sizes[0] == 0 {
			continue
		}
		pkt := bufs[0][:sizes[0]]
		if err := c.sendData(pppEncode(pppIP, pkt)); err != nil {
			return
		}
	}
}

// selfSignedCert generates a throwaway ECDSA certificate for the TLS listener.
func selfSignedCert() (tls.Certificate, []byte, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "sstp-test-server"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	cert := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv}
	return cert, der, nil
}

// CertSHA256 returns the SHA-256 of the server certificate (for reference).
func (s *Server) CertSHA256() [32]byte { return sha256.Sum256(s.certDER) }

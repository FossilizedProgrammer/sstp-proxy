// Package sstp implements the client side of Microsoft's Secure Socket
// Tunneling Protocol (MS-SSTP) as spoken by Windows RRAS, MikroTik RouterOS
// and SoftEther VPN Server (including public VPN Gate relays).
//
// SSTP carries a PPP session inside an HTTPS (TLS) tunnel on TCP/443. This
// package handles only the outer SSTP framing and control-message state
// machine; the inner PPP negotiation lives in the ppp package.
package sstp

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

// SSTP protocol constants (see [MS-SSTP]).
const (
	Version = 0x10 // Major 1, Minor 0

	// Control message types.
	MsgCallConnectRequest = 0x0001
	MsgCallConnectAck     = 0x0002
	MsgCallConnectNak     = 0x0003
	MsgCallConnected      = 0x0004
	MsgCallAbort          = 0x0005
	MsgCallDisconnect     = 0x0006
	MsgCallDisconnectAck  = 0x0007
	MsgEchoRequest        = 0x0008
	MsgEchoResponse       = 0x0009

	// Attribute IDs.
	AttrEncapsulatedProtocolID = 0x01
	AttrStatusInfo             = 0x02
	AttrCryptoBinding          = 0x03
	AttrCryptoBindingReq       = 0x04

	// Encapsulated protocol.
	EncapProtocolPPP = 0x0001

	// Certificate hash protocol bitmask values.
	CertHashProtocolSHA1   = 0x01
	CertHashProtocolSHA256 = 0x02

	// The magic URI used by every SSTP server implementation.
	uri = "/sra_{BA195980-CD49-458b-9E23-C84EE0ADCD75}/"
)

// Conn is an established SSTP tunnel. It is safe to call Send* concurrently
// with Recv, but the individual Send* methods must not be called from
// multiple goroutines at once (the tunnel serialises writes for us).
type Conn struct {
	tls  net.Conn // standard *tls.Conn or uTLS *utls.UConn
	br   *bufio.Reader
	Cert []byte // DER bytes of the server leaf certificate
}

// Packet is a parsed SSTP packet.
type Packet struct {
	Control bool
	MsgType uint16   // valid when Control
	Attrs   []Attr   // valid when Control
	Data    []byte   // PPP frame payload when !Control
	Raw     []byte   // full packet bytes (used for control validation)
}

// Attr is a single SSTP attribute.
type Attr struct {
	ID    byte
	Value []byte
}

// DialContextFunc dials a raw TCP connection to addr, optionally through a
// proxy. When nil, a direct net.Dialer is used.
type DialContextFunc func(ctx context.Context, network, addr string) (net.Conn, error)

// DialOptions configures how the SSTP/TLS connection is established. Beyond the
// basics it exposes several anti-censorship knobs (custom SNI, domain fronting
// and a uTLS browser fingerprint) for use where DPI blocks straightforward SSTP.
type DialOptions struct {
	// Server is the logical VPN server address (host or host:port). It is used
	// as the default for SNI, the HTTP Host header and the TCP connect target.
	Server string
	// ConnectAddr, when set, is the actual TCP endpoint to dial (host or
	// host:port). This enables domain fronting: connect to one address while
	// presenting a different SNI/Host.
	ConnectAddr string
	// ServerName overrides the TLS SNI. Use "-" to send no SNI at all. Empty
	// means "derive from Server".
	ServerName string
	// HostHeader overrides the HTTP Host header. Empty means "use ServerName".
	HostHeader string
	// Fingerprint selects a uTLS ClientHello ("chrome", "firefox", "safari",
	// "edge", "ios", "random"). Empty uses the standard Go TLS stack.
	Fingerprint string
	// Insecure skips TLS certificate verification (usually required for
	// SoftEther/VPN Gate self-signed certificates).
	Insecure bool
	// Timeout bounds the connect + handshake + HTTP negotiation.
	Timeout time.Duration
	// DialFn, when set, establishes the raw TCP connection (e.g. through a
	// proxy). When nil a direct net.Dialer is used.
	DialFn DialContextFunc
}

// Dial opens the TLS connection, performs the SSTP HTTP handshake and returns a
// ready-to-negotiate Conn. It does not send CALL_CONNECT_REQUEST.
func Dial(opts DialOptions) (*Conn, error) {
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}

	// The logical server host (for defaults).
	host, _, err := net.SplitHostPort(opts.Server)
	if err != nil {
		host = opts.Server
	}

	// The TCP endpoint to actually dial.
	connectTarget := opts.Server
	if opts.ConnectAddr != "" {
		connectTarget = opts.ConnectAddr
	}
	cHost, cPort, err := net.SplitHostPort(connectTarget)
	if err != nil {
		cHost = connectTarget
		cPort = "443"
	}

	// SNI resolution: "-" => no SNI, empty => host, else literal.
	sni := host
	switch opts.ServerName {
	case "-":
		sni = ""
	case "":
		// keep host
	default:
		sni = opts.ServerName
	}

	// HTTP Host header: explicit override, else the SNI (or host if no SNI).
	hostHeader := opts.HostHeader
	if hostHeader == "" {
		if sni != "" {
			hostHeader = sni
		} else {
			hostHeader = host
		}
	}

	dialFn := opts.DialFn
	if dialFn == nil {
		d := &net.Dialer{Timeout: timeout}
		dialFn = d.DialContext
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	raw, err := dialFn(ctx, "tcp", net.JoinHostPort(cHost, cPort))
	if err != nil {
		return nil, fmt.Errorf("tcp connect: %w", err)
	}

	tc, leaf, err := handshakeTLS(raw, sni, opts.Insecure, opts.Fingerprint, timeout)
	if err != nil {
		raw.Close()
		return nil, err
	}

	// SSTP HTTP negotiation. Content-Length is the maximum possible value so
	// the connection is treated as an infinite bidirectional stream.
	req := "SSTP_DUPLEX_POST " + uri + " HTTP/1.1\r\n" +
		"Host: " + hostHeader + "\r\n" +
		"SSTPCORRELATIONID: {" + newGUID() + "}\r\n" +
		"Content-Length: 18446744073709551615\r\n" +
		"\r\n"
	tc.SetWriteDeadline(time.Now().Add(timeout))
	if _, err := io.WriteString(tc, req); err != nil {
		tc.Close()
		return nil, fmt.Errorf("write http request: %w", err)
	}
	tc.SetWriteDeadline(time.Time{})

	br := bufio.NewReaderSize(tc, 65536)
	tc.SetReadDeadline(time.Now().Add(timeout))
	statusLine, err := br.ReadString('\n')
	if err != nil {
		tc.Close()
		return nil, fmt.Errorf("read http status: %w", err)
	}
	if !strings.Contains(statusLine, " 200") {
		tc.Close()
		return nil, fmt.Errorf("unexpected SSTP http status: %q", strings.TrimSpace(statusLine))
	}
	// Drain remaining headers up to the blank line.
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			tc.Close()
			return nil, fmt.Errorf("read http headers: %w", err)
		}
		if strings.TrimSpace(line) == "" {
			break
		}
	}
	tc.SetReadDeadline(time.Time{})

	return &Conn{tls: tc, br: br, Cert: leaf}, nil
}

// CertHash returns the SHA-256 hash of the server leaf certificate, used for
// the SSTP crypto binding.
func (c *Conn) CertHashSHA256() [32]byte {
	return sha256.Sum256(c.Cert)
}

// Close tears the tunnel down.
func (c *Conn) Close() error { return c.tls.Close() }

// Recv reads and parses the next SSTP packet from the wire.
func (c *Conn) Recv() (*Packet, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(c.br, hdr[:]); err != nil {
		return nil, err
	}
	if hdr[0] != Version {
		return nil, fmt.Errorf("bad SSTP version 0x%02x", hdr[0])
	}
	length := int(binary.BigEndian.Uint16(hdr[2:4]) & 0x0FFF)
	if length < 4 {
		return nil, fmt.Errorf("invalid SSTP length %d", length)
	}
	body := make([]byte, length-4)
	if _, err := io.ReadFull(c.br, body); err != nil {
		return nil, err
	}
	raw := append(append([]byte{}, hdr[:]...), body...)

	pkt := &Packet{Control: hdr[1]&0x01 != 0, Raw: raw}
	if !pkt.Control {
		pkt.Data = body
		return pkt, nil
	}
	if len(body) < 4 {
		return nil, errors.New("control packet too short")
	}
	pkt.MsgType = binary.BigEndian.Uint16(body[0:2])
	numAttr := int(binary.BigEndian.Uint16(body[2:4]))
	off := 4
	for i := 0; i < numAttr; i++ {
		if off+4 > len(body) {
			return nil, errors.New("truncated SSTP attribute")
		}
		id := body[off+1]
		alen := int(binary.BigEndian.Uint16(body[off+2 : off+4]) & 0x0FFF)
		if alen < 4 || off+alen > len(body) {
			return nil, errors.New("invalid SSTP attribute length")
		}
		pkt.Attrs = append(pkt.Attrs, Attr{ID: id, Value: body[off+4 : off+alen]})
		off += alen
	}
	return pkt, nil
}

// SendData wraps a PPP frame in an SSTP data packet and writes it.
func (c *Conn) SendData(ppp []byte) error {
	total := 4 + len(ppp)
	buf := make([]byte, total)
	buf[0] = Version
	buf[1] = 0x00 // data packet
	binary.BigEndian.PutUint16(buf[2:4], uint16(total))
	copy(buf[4:], ppp)
	_, err := c.tls.Write(buf)
	return err
}

// SendControl builds and writes an SSTP control packet from raw attributes.
func (c *Conn) SendControl(msgType uint16, attrs []byte, numAttrs int) error {
	total := 8 + len(attrs)
	buf := make([]byte, total)
	buf[0] = Version
	buf[1] = 0x01 // control packet
	binary.BigEndian.PutUint16(buf[2:4], uint16(total))
	binary.BigEndian.PutUint16(buf[4:6], msgType)
	binary.BigEndian.PutUint16(buf[6:8], uint16(numAttrs))
	copy(buf[8:], attrs)
	_, err := c.tls.Write(buf)
	return err
}

// BuildControl assembles a control packet into a buffer without writing it.
// Useful when the packet bytes are needed to compute a MAC over them.
func BuildControl(msgType uint16, attrs []byte, numAttrs int) []byte {
	total := 8 + len(attrs)
	buf := make([]byte, total)
	buf[0] = Version
	buf[1] = 0x01
	binary.BigEndian.PutUint16(buf[2:4], uint16(total))
	binary.BigEndian.PutUint16(buf[4:6], msgType)
	binary.BigEndian.PutUint16(buf[6:8], uint16(numAttrs))
	copy(buf[8:], attrs)
	return buf
}

// WriteRaw writes pre-assembled packet bytes directly to the tunnel.
func (c *Conn) WriteRaw(b []byte) error {
	_, err := c.tls.Write(b)
	return err
}

// BuildAttr encodes a single SSTP attribute (reserved + id + length + value).
func BuildAttr(id byte, value []byte) []byte {
	out := make([]byte, 4+len(value))
	out[0] = 0x00
	out[1] = id
	binary.BigEndian.PutUint16(out[2:4], uint16(4+len(value)))
	copy(out[4:], value)
	return out
}

// Package tunnel wires the SSTP transport, PPP negotiation, userspace network
// stack and local proxy servers into a single running client.
package tunnel

import (
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"sstpproxy/internal/ppp"
	"sstpproxy/internal/proxy"
	"sstpproxy/internal/sstp"
	"sstpproxy/internal/upstream"
	"sstpproxy/internal/vnet"
)

// keepAliveInterval must stay well under SoftEther's 20-second SSTP_TIMEOUT so
// idle sessions are not dropped by the server.
const keepAliveInterval = 8 * time.Second

// Config configures a tunnel run.
type Config struct {
	Server    string
	Username  string
	Password  string
	Auth      ppp.AuthPref
	Insecure  bool
	SocksAddr string
	HTTPAddr  string
	MTU       int
	ExtraDNS  []net.IP
	Proxy     string // upstream proxy URL for the SSTP connection (optional)

	// Anti-censorship / DPI-evasion knobs.
	ConnectAddr string // actual TCP endpoint to dial (domain fronting)
	SNI         string // TLS SNI override ("-" = none)
	HostHeader  string // HTTP Host header override
	Fingerprint string // uTLS browser fingerprint

	Verbose bool
}

type tunnel struct {
	cfg  Config
	conn *sstp.Conn
	sess *ppp.Session

	writeMu sync.Mutex

	nonce        []byte
	useSHA256    bool
	hashBitmask  byte

	vnetMu    sync.Mutex
	vn        *vnet.Net
	listeners []net.Listener

	lastRecv atomic.Int64 // unix-nano timestamp of last packet from server

	errCh chan error
	once  sync.Once
}

func (t *tunnel) logf(format string, a ...any) {
	fmt.Printf("[sstp] "+format+"\n", a...)
}

func (t *tunnel) vlogf(format string, a ...any) {
	if t.cfg.Verbose {
		fmt.Printf("[dbg] "+format+"\n", a...)
	}
}

func orDefault(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

func (t *tunnel) reportErr(err error) {
	t.once.Do(func() { t.errCh <- err })
}

// Run establishes the tunnel and blocks until it fails or ctx is cancelled.
func Run(ctx context.Context, cfg Config) error {
	if cfg.MTU == 0 {
		cfg.MTU = 1400
	}
	t := &tunnel{cfg: cfg, errCh: make(chan error, 1)}

	dialFn, err := upstream.FromURL(cfg.Proxy, 30*time.Second)
	if err != nil {
		return err
	}
	if cfg.Proxy != "" {
		t.logf("connecting to %s via proxy %s ...", cfg.Server, cfg.Proxy)
	} else {
		t.logf("connecting to %s ...", cfg.Server)
	}
	if cfg.ConnectAddr != "" {
		t.logf("  domain fronting: dialing %s", cfg.ConnectAddr)
	}
	if cfg.SNI != "" || cfg.Fingerprint != "" {
		sniDesc := cfg.SNI
		if sniDesc == "-" {
			sniDesc = "(none)"
		} else if sniDesc == "" {
			sniDesc = "(default)"
		}
		t.logf("  TLS SNI: %s  fingerprint: %s", sniDesc, orDefault(cfg.Fingerprint, "(standard)"))
	}
	conn, err := sstp.Dial(sstp.DialOptions{
		Server:      cfg.Server,
		ConnectAddr: cfg.ConnectAddr,
		ServerName:  cfg.SNI,
		HostHeader:  cfg.HostHeader,
		Fingerprint: cfg.Fingerprint,
		Insecure:    cfg.Insecure,
		Timeout:     30 * time.Second,
		DialFn:      sstp.DialContextFunc(dialFn),
	})
	if err != nil {
		return err
	}
	t.conn = conn
	// Defers run LIFO: close the SSTP transport first so no new packets can be
	// injected, then run cleanup (which drains and releases the netstack).
	defer t.cleanup()
	defer conn.Close()
	t.lastRecv.Store(time.Now().UnixNano())
	t.logf("TLS established; starting SSTP handshake")

	// Send CALL_CONNECT_REQUEST (encapsulated protocol = PPP).
	attr := sstp.BuildAttr(sstp.AttrEncapsulatedProtocolID, []byte{0x00, 0x01})
	if err := t.sendControl(sstp.MsgCallConnectRequest, attr, 1); err != nil {
		return err
	}

	go t.readLoop()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-t.errCh:
		return err
	}
}

func (t *tunnel) readLoop() {
	for {
		pkt, err := t.conn.Recv()
		if err != nil {
			t.reportErr(fmt.Errorf("tunnel closed: %w", err))
			return
		}
		t.lastRecv.Store(time.Now().UnixNano())
		if pkt.Control {
			t.handleControl(pkt)
		} else if t.sess != nil {
			t.sess.HandleFrame(pkt.Data)
		}
	}
}

// keepAlive periodically sends an SSTP echo request so the server never hits
// its 20-second idle timeout, and aborts the tunnel if the server has gone
// silent for too long (indicating a dead connection).
func (t *tunnel) keepAlive() {
	ticker := time.NewTicker(keepAliveInterval)
	defer ticker.Stop()
	for range ticker.C {
		if err := t.sendControl(sstp.MsgEchoRequest, nil, 0); err != nil {
			t.reportErr(fmt.Errorf("keepalive send failed: %w", err))
			return
		}
		last := t.lastRecv.Load()
		if last != 0 && time.Since(time.Unix(0, last)) > 3*keepAliveInterval+SSTPServerTimeout {
			t.reportErr(fmt.Errorf("no response from server for too long; connection appears dead"))
			return
		}
	}
}

// SSTPServerTimeout mirrors SoftEther's SSTP_TIMEOUT (20s).
const SSTPServerTimeout = 20 * time.Second

func (t *tunnel) handleControl(pkt *sstp.Packet) {
	switch pkt.MsgType {
	case sstp.MsgCallConnectAck:
		t.onConnectAck(pkt)
	case sstp.MsgCallConnectNak:
		t.reportErr(fmt.Errorf("server rejected connection (CALL_CONNECT_NAK)"))
	case sstp.MsgCallAbort:
		t.reportErr(fmt.Errorf("server aborted the call (CALL_ABORT)"))
	case sstp.MsgCallDisconnect:
		t.reportErr(fmt.Errorf("server disconnected the call"))
	case sstp.MsgEchoRequest:
		_ = t.sendControl(sstp.MsgEchoResponse, nil, 0)
	}
}

func (t *tunnel) onConnectAck(pkt *sstp.Packet) {
	// Extract the crypto-binding request: reserved(3) + bitmask(1) + nonce(32).
	for _, a := range pkt.Attrs {
		if a.ID == sstp.AttrCryptoBindingReq && len(a.Value) >= 36 {
			t.hashBitmask = a.Value[3]
			t.nonce = append([]byte{}, a.Value[4:36]...)
			t.useSHA256 = t.hashBitmask&sstp.CertHashProtocolSHA256 != 0
		}
	}
	t.logf("CALL_CONNECT_ACK received; negotiating PPP (crypto hash=%s)", t.hashName())

	go t.keepAlive()

	t.sess = &ppp.Session{
		Username:    t.cfg.Username,
		Password:    t.cfg.Password,
		AuthPref:    t.cfg.Auth,
		MTU:         t.cfg.MTU,
		Send:        t.sendFrame,
		Log:         t.vlogf,
		OnAuthDone:  t.onAuthDone,
		OnNetworkUp: t.onNetworkUp,
		OnIPPacket:  t.onIPPacket,
		OnError:     t.reportErr,
	}
	t.sess.Start()
}

func (t *tunnel) hashName() string {
	if t.useSHA256 {
		return "SHA256"
	}
	return "SHA1"
}

// onAuthDone sends the SSTP CALL_CONNECTED message carrying the crypto binding.
func (t *tunnel) onAuthDone(hlak []byte) {
	t.logf("PPP authentication complete; sending crypto binding")

	var certHash []byte
	if t.useSHA256 {
		h := sha256.Sum256(t.conn.Cert)
		certHash = h[:]
	} else {
		h := sha1.Sum(t.conn.Cert)
		certHash = h[:]
	}
	bitmask := byte(sstp.CertHashProtocolSHA1)
	if t.useSHA256 {
		bitmask = sstp.CertHashProtocolSHA256
	}

	// Crypto binding attribute value:
	// reserved(3) + hashBitmask(1) + nonce(32) + certHash(32) + MAC(32).
	value := make([]byte, 100)
	value[3] = bitmask
	copy(value[4:36], t.nonce)
	copy(value[36:68], certHash) // zero padded for SHA1

	attr := sstp.BuildAttr(sstp.AttrCryptoBinding, value)
	msg := sstp.BuildControl(sstp.MsgCallConnected, attr, 1)

	// MAC field position: 8 (sstp hdr) + 4 (attr hdr) + 68 (value offset) = 80.
	cmk := ppp.ComputeCMK(hlak, t.useSHA256)
	cmac := ppp.ComputeCMAC(cmk, msg, t.useSHA256)
	copy(msg[80:80+len(cmac)], cmac)

	t.writeMu.Lock()
	err := t.conn.WriteRaw(msg)
	t.writeMu.Unlock()
	if err != nil {
		t.reportErr(fmt.Errorf("send CALL_CONNECTED: %w", err))
	}
}

func (t *tunnel) onNetworkUp(cfg ppp.NetConfig) {
	dns := append([]net.IP{}, cfg.DNS...)
	dns = append(dns, t.cfg.ExtraDNS...)
	vn, err := vnet.New(cfg.LocalIP, dns, t.cfg.MTU)
	if err != nil {
		t.reportErr(fmt.Errorf("init userspace network: %w", err))
		return
	}
	t.vnetMu.Lock()
	t.vn = vn
	t.vnetMu.Unlock()

	// Pump outbound packets from the stack into the tunnel.
	go t.outboundPump()

	if err := t.startProxies(vn); err != nil {
		t.reportErr(err)
		return
	}
	t.logf("tunnel is UP  (assigned IP %s)", cfg.LocalIP)
	t.logf("proxies ready: %s", proxy.StatusString(t.cfg.SocksAddr, t.cfg.HTTPAddr))
	t.logf("configure your browser to use one of the above and your traffic exits via the VPN server")
}

func (t *tunnel) startProxies(vn *vnet.Net) error {
	if t.cfg.SocksAddr != "" {
		ln, err := net.Listen("tcp", t.cfg.SocksAddr)
		if err != nil {
			return fmt.Errorf("listen SOCKS %s: %w", t.cfg.SocksAddr, err)
		}
		t.listeners = append(t.listeners, ln)
		go func() {
			if err := proxy.ServeSOCKS(ln, vn, t.proxyLog); err != nil {
				t.vlogf("socks server stopped: %v", err)
			}
		}()
	}
	if t.cfg.HTTPAddr != "" {
		ln, err := net.Listen("tcp", t.cfg.HTTPAddr)
		if err != nil {
			return fmt.Errorf("listen HTTP %s: %w", t.cfg.HTTPAddr, err)
		}
		t.listeners = append(t.listeners, ln)
		go func() {
			if err := proxy.ServeHTTP(ln, vn, t.proxyLog); err != nil {
				t.vlogf("http server stopped: %v", err)
			}
		}()
	}
	return nil
}

// cleanup releases the OS-level TCP listeners so a subsequent retry can rebind
// the same local proxy addresses.
//
// It intentionally does NOT close the userspace netstack device. gVisor keeps
// firing TCP timers (retransmit/probe) on endpoints that are still tearing down
// and those handlers write into the netstack's internal channel; the
// wireguard-go netstack Close() closes that same channel, so closing it while
// any endpoint is alive is an unavoidable data race in that library. The
// netstack binds no OS-level resources (no real sockets/ports), so it is simply
// reclaimed once unreferenced and at process exit. On -retry this leaks one
// netstack per reconnect, which is bounded and acceptable in exchange for a
// race-free, panic-free shutdown.
func (t *tunnel) cleanup() {
	for _, ln := range t.listeners {
		_ = ln.Close()
	}
	t.listeners = nil
	t.vnetMu.Lock()
	t.vn = nil
	t.vnetMu.Unlock()
}

func (t *tunnel) proxyLog(format string, a ...any) {
	t.vlogf(format, a...)
}

func (t *tunnel) outboundPump() {
	t.vnetMu.Lock()
	vn := t.vn
	t.vnetMu.Unlock()
	for {
		pkt, err := vn.ReadOutbound()
		if err != nil {
			return
		}
		if len(pkt) == 0 {
			continue
		}
		if err := t.sess.SendIP(pkt); err != nil {
			t.reportErr(fmt.Errorf("send IP: %w", err))
			return
		}
	}
}

func (t *tunnel) onIPPacket(pkt []byte) {
	t.vnetMu.Lock()
	vn := t.vn
	t.vnetMu.Unlock()
	if vn != nil {
		_ = vn.WriteInbound(pkt)
	}
}

// sendFrame is the PPP layer's transmit hook (serialised with all other writes).
func (t *tunnel) sendFrame(frame []byte) error {
	t.writeMu.Lock()
	defer t.writeMu.Unlock()
	return t.conn.SendData(frame)
}

func (t *tunnel) sendControl(msgType uint16, attrs []byte, numAttrs int) error {
	t.writeMu.Lock()
	defer t.writeMu.Unlock()
	return t.conn.SendControl(msgType, attrs, numAttrs)
}

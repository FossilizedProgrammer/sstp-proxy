package ppp

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"sync"
)

// AuthPref selects which PPP authentication method to prefer/allow.
type AuthPref int

const (
	AuthAuto AuthPref = iota
	AuthMSCHAPv2
	AuthPAP
)

// NetConfig is the result of successful IPCP negotiation.
type NetConfig struct {
	LocalIP net.IP
	DNS     []net.IP
}

type phase int

const (
	phaseLCP phase = iota
	phaseAuth
	phaseNetwork
	phaseUp
	phaseDead
)

// Session drives the inner PPP negotiation over an SSTP data channel.
type Session struct {
	mu sync.Mutex

	Username string
	Password string
	AuthPref AuthPref
	MTU      int

	// Send transmits a fully framed PPP packet over the SSTP data channel.
	Send func(frame []byte) error
	// Log receives human-readable progress messages.
	Log func(format string, args ...any)
	// OnAuthDone fires once higher-layer auth completes; hlak is the 32-byte
	// HLAK (zeroed for PAP / no-auth) used for the SSTP crypto binding.
	OnAuthDone func(hlak []byte)
	// OnNetworkUp fires when IPCP has assigned an address.
	OnNetworkUp func(cfg NetConfig)
	// OnIPPacket delivers an inbound IPv4 packet to the caller.
	OnIPPacket func(pkt []byte)
	// OnError fires on a fatal negotiation error.
	OnError func(err error)

	ph phase

	// LCP state
	lcpID          byte
	lcpMagic       uint32
	lcpLocalAcked  bool
	lcpRemoteAcked bool
	lcpWantMRU     bool // include the MRU option in our Configure-Request
	lcpWantMagic   bool // include the Magic-Number option
	lcpRetries     int  // guards against endless Reject/Nak loops

	// negotiated auth
	authProto uint16
	chapAlgo  byte

	// IPCP state
	ipcpID         byte
	ipcpLocalAcked bool
	ipcpRemoteAcked bool
	localIP        net.IP
	priDNS         net.IP
	secDNS         net.IP

	authDone    bool
	networkDone bool

	lastChallengeID byte
	pendingMSCHAP   *mschapv2
}

func (s *Session) logf(f string, a ...any) {
	if s.Log != nil {
		s.Log(f, a...)
	}
}

func (s *Session) fail(err error) {
	s.ph = phaseDead
	if s.OnError != nil {
		s.OnError(err)
	}
}

// Start kicks off LCP by sending the first Configure-Request.
func (s *Session) Start() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.MTU == 0 {
		s.MTU = 1400
	}
	var m [4]byte
	_, _ = rand.Read(m[:])
	s.lcpMagic = binary.BigEndian.Uint32(m[:])
	s.ph = phaseLCP
	s.lcpID = 1
	s.lcpWantMRU = true
	s.lcpWantMagic = true
	s.sendLCPConfigReq()
}

// SendIP frames and transmits an outbound IPv4 packet from the netstack.
func (s *Session) SendIP(pkt []byte) error {
	s.mu.Lock()
	up := s.ph == phaseUp
	s.mu.Unlock()
	if !up {
		return nil
	}
	return s.Send(encodeFrame(ProtoIP, pkt))
}

// HandleFrame processes a single inbound PPP frame delivered by the SSTP layer.
func (s *Session) HandleFrame(frame []byte) {
	proto, payload, ok := decodeFrame(frame)
	if !ok {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	switch proto {
	case ProtoLCP:
		s.handleLCP(payload)
	case ProtoCHAP:
		s.handleCHAP(payload)
	case ProtoPAP:
		s.handlePAP(payload)
	case ProtoIPCP:
		s.handleIPCP(payload)
	case ProtoIP:
		if s.ph == phaseUp && s.OnIPPacket != nil {
			cp := make([]byte, len(payload))
			copy(cp, payload)
			s.OnIPPacket(cp)
		}
	case ProtoIPV6CP:
		// Reject IPv6CP so the server stops proposing it.
		if len(payload) >= 4 && payload[0] == CodeConfigureRequest {
			s.Send(encodeFrame(ProtoIPV6CP, encodeControl(CodeConfigureReject, payload[1], payload[4:parseLen(payload)])))
		}
	default:
		// Reject unknown network-layer protocols.
		rej := make([]byte, 2+len(payload))
		binary.BigEndian.PutUint16(rej[0:2], proto)
		copy(rej[2:], payload)
		s.Send(encodeFrame(ProtoLCP, encodeControl(CodeProtocolReject, s.nextID(), rej)))
	}
}

func parseLen(p []byte) int {
	if len(p) < 4 {
		return len(p)
	}
	l := int(binary.BigEndian.Uint16(p[2:4]))
	if l > len(p) || l < 4 {
		return len(p)
	}
	return l
}

var idCounter byte

func (s *Session) nextID() byte {
	idCounter++
	return idCounter
}

// ---------------- LCP ----------------

func (s *Session) sendLCPConfigReq() {
	var opts []byte
	if s.lcpWantMRU {
		mru := make([]byte, 4)
		mru[0] = lcpOptMRU
		mru[1] = 4
		binary.BigEndian.PutUint16(mru[2:4], uint16(s.MTU))
		opts = append(opts, mru...)
	}
	if s.lcpWantMagic {
		mg := make([]byte, 6)
		mg[0] = lcpOptMagic
		mg[1] = 6
		binary.BigEndian.PutUint32(mg[2:6], s.lcpMagic)
		opts = append(opts, mg...)
	}
	// An empty Configure-Request (no options) is perfectly valid per RFC 1661
	// and is what we fall back to if the server rejects everything we offer.
	s.logf("LCP: sending Configure-Request (id=%d, %d option bytes)", s.lcpID, len(opts))
	s.Send(encodeFrame(ProtoLCP, encodeControl(CodeConfigureRequest, s.lcpID, opts)))
}

func (s *Session) handleLCP(p []byte) {
	if len(p) < 4 {
		return
	}
	code := p[0]
	id := p[1]
	length := int(binary.BigEndian.Uint16(p[2:4]))
	if length > len(p) {
		length = len(p)
	}
	data := p[4:length]

	switch code {
	case CodeConfigureRequest:
		s.handleLCPConfigReq(id, data)
	case CodeConfigureAck:
		if id == s.lcpID {
			s.lcpLocalAcked = true
			s.logf("LCP: our Configure-Request acked")
			s.maybeLCPUp()
		}
	case CodeConfigureNak:
		if s.lcpRetries++; s.lcpRetries > 20 {
			s.fail(fmt.Errorf("LCP negotiation failed: too many Configure-Nak/Reject rounds"))
			return
		}
		s.applyLCPNak(data)
		s.lcpID++
		s.logf("LCP: got Configure-Nak; adjusting and retrying")
		s.sendLCPConfigReq()
	case CodeConfigureReject:
		if s.lcpRetries++; s.lcpRetries > 20 {
			s.fail(fmt.Errorf("LCP negotiation failed: too many Configure-Reject rounds"))
			return
		}
		s.applyLCPReject(data)
		s.lcpID++
		s.logf("LCP: got Configure-Reject; dropping rejected options and retrying")
		s.sendLCPConfigReq()
	case CodeEchoRequest:
		// Reply with our magic number.
		reply := make([]byte, 4+len(data))
		binary.BigEndian.PutUint32(reply[0:4], s.lcpMagic)
		if len(data) > 4 {
			copy(reply[4:], data[4:])
		}
		s.Send(encodeFrame(ProtoLCP, encodeControl(CodeEchoReply, id, reply[:4])))
	case CodeTerminateRequest:
		s.Send(encodeFrame(ProtoLCP, encodeControl(CodeTerminateAck, id, nil)))
		s.fail(fmt.Errorf("server terminated LCP"))
	case CodeCodeReject, CodeProtocolReject:
		// ignore
	}
}

// applyLCPReject removes every option the peer rejected from our next
// Configure-Request. Rejecting an option we did not send is ignored.
func (s *Session) applyLCPReject(opts []byte) {
	i := 0
	for i+2 <= len(opts) {
		t := opts[i]
		l := int(opts[i+1])
		if l < 2 || i+l > len(opts) {
			break
		}
		switch t {
		case lcpOptMRU:
			s.lcpWantMRU = false
		case lcpOptMagic:
			s.lcpWantMagic = false
		}
		i += l
	}
}

// applyLCPNak applies the peer's suggested values. For the Magic-Number the
// only sensible reaction is to pick a fresh random value; other options are
// simply re-offered with the suggested value where we care.
func (s *Session) applyLCPNak(opts []byte) {
	i := 0
	for i+2 <= len(opts) {
		t := opts[i]
		l := int(opts[i+1])
		if l < 2 || i+l > len(opts) {
			break
		}
		v := opts[i+2 : i+l]
		switch t {
		case lcpOptMagic:
			if len(v) == 4 {
				// Avoid collision the peer complained about: reroll.
				var m [4]byte
				_, _ = rand.Read(m[:])
				s.lcpMagic = binary.BigEndian.Uint32(m[:])
			}
		case lcpOptMRU:
			if len(v) == 2 {
				if mru := int(binary.BigEndian.Uint16(v)); mru >= 576 && mru <= 1500 {
					s.MTU = mru
				}
			}
		}
		i += l
	}
}

func (s *Session) handleLCPConfigReq(id byte, opts []byte) {
	var reject []byte
	var accepted []byte
	i := 0
	for i+2 <= len(opts) {
		t := opts[i]
		l := int(opts[i+1])
		if l < 2 || i+l > len(opts) {
			break
		}
		val := opts[i : i+l]
		switch t {
		case lcpOptMRU, lcpOptMagic, lcpOptPFC, lcpOptACFC:
			accepted = append(accepted, val...)
		case lcpOptAuth:
			if l >= 4 {
				proto := binary.BigEndian.Uint16(opts[i+2 : i+4])
				algo := byte(0)
				if l >= 5 {
					algo = opts[i+4]
				}
				if s.acceptAuth(proto, algo) {
					s.authProto = proto
					s.chapAlgo = algo
					accepted = append(accepted, val...)
				} else {
					// Nak to propose an acceptable method below.
					reject = append(reject, val...)
				}
			} else {
				reject = append(reject, val...)
			}
		default:
			reject = append(reject, val...)
		}
		i += l
	}

	if len(reject) > 0 {
		s.logf("LCP: rejecting %d bytes of unacceptable options", len(reject))
		s.Send(encodeFrame(ProtoLCP, encodeControl(CodeConfigureReject, id, reject)))
		return
	}
	s.logf("LCP: acking server Configure-Request (auth proto=0x%04x algo=0x%02x)", s.authProto, s.chapAlgo)
	s.Send(encodeFrame(ProtoLCP, encodeControl(CodeConfigureAck, id, accepted)))
	s.lcpRemoteAcked = true
	s.maybeLCPUp()
}

func (s *Session) acceptAuth(proto uint16, algo byte) bool {
	switch s.AuthPref {
	case AuthPAP:
		return proto == ProtoPAP
	case AuthMSCHAPv2:
		return proto == ProtoCHAP && algo == chapAlgoMSCHAPv2
	default: // auto
		if proto == ProtoPAP {
			return true
		}
		if proto == ProtoCHAP && (algo == chapAlgoMSCHAPv2 || algo == chapAlgoMD5) {
			return true
		}
		return false
	}
}

func (s *Session) maybeLCPUp() {
	if s.ph != phaseLCP || !s.lcpLocalAcked || !s.lcpRemoteAcked {
		return
	}
	s.ph = phaseAuth
	s.logf("LCP up; entering authentication phase")
	if s.authProto == ProtoPAP {
		s.sendPAP()
	} else if s.authProto == 0 {
		// server never asked for auth
		s.completeAuth(nil)
	}
	// For CHAP we wait for the server challenge.
}

// ---------------- Authentication ----------------

func (s *Session) sendPAP() {
	u := []byte(s.Username)
	p := []byte(s.Password)
	data := make([]byte, 0, 2+len(u)+len(p))
	data = append(data, byte(len(u)))
	data = append(data, u...)
	data = append(data, byte(len(p)))
	data = append(data, p...)
	s.logf("PAP: sending Authenticate-Request")
	s.Send(encodeFrame(ProtoPAP, encodeControl(PAPAuthenticateRequest, s.nextID(), data)))
}

func (s *Session) handlePAP(p []byte) {
	if len(p) < 4 {
		return
	}
	switch p[0] {
	case PAPAuthenticateAck:
		s.logf("PAP: authentication succeeded")
		s.completeAuth(nil)
	case PAPAuthenticateNak:
		s.fail(fmt.Errorf("PAP authentication failed (wrong username/password?)"))
	}
}

func (s *Session) handleCHAP(p []byte) {
	if len(p) < 4 {
		return
	}
	code := p[0]
	id := p[1]
	length := int(binary.BigEndian.Uint16(p[2:4]))
	if length > len(p) {
		length = len(p)
	}
	data := p[4:length]

	switch code {
	case CHAPChallenge:
		if len(data) < 1 {
			return
		}
		vs := int(data[0])
		if 1+vs > len(data) {
			return
		}
		challenge := data[1 : 1+vs]
		s.lastChallengeID = id
		if s.chapAlgo == chapAlgoMSCHAPv2 {
			s.respondMSCHAPv2(id, challenge)
		} else {
			s.respondCHAPMD5(id, challenge)
		}
	case CHAPSuccess:
		s.logf("CHAP: authentication succeeded")
		s.finishCHAPAuth()
	case CHAPFailure:
		s.fail(fmt.Errorf("CHAP authentication failed: %s", string(data)))
	}
}

func (s *Session) respondMSCHAPv2(id byte, challenge []byte) {
	m := newMSCHAPv2(s.Username, s.Password, challenge)
	s.pendingMSCHAP = m
	val := m.responseValue()
	u := []byte(s.Username)
	data := make([]byte, 0, 1+len(val)+len(u))
	data = append(data, byte(len(val)))
	data = append(data, val...)
	data = append(data, u...)
	s.logf("MS-CHAPv2: sending Response")
	s.Send(encodeFrame(ProtoCHAP, encodeControl(CHAPResponse, id, data)))
}

func (s *Session) respondCHAPMD5(id byte, challenge []byte) {
	resp := chapMD5Response(id, s.Password, challenge)
	u := []byte(s.Username)
	data := make([]byte, 0, 1+len(resp)+len(u))
	data = append(data, byte(len(resp)))
	data = append(data, resp...)
	data = append(data, u...)
	s.logf("CHAP-MD5: sending Response")
	s.Send(encodeFrame(ProtoCHAP, encodeControl(CHAPResponse, id, data)))
}

func (s *Session) finishCHAPAuth() {
	var hlak []byte
	if s.pendingMSCHAP != nil {
		hlak = s.pendingMSCHAP.HLAK()
	}
	s.completeAuth(hlak)
}

func (s *Session) completeAuth(hlak []byte) {
	if s.authDone {
		return
	}
	s.authDone = true
	if hlak == nil {
		hlak = make([]byte, 32)
	}
	if s.OnAuthDone != nil {
		s.OnAuthDone(hlak)
	}
	s.ph = phaseNetwork
	s.ipcpID = 1
	s.sendIPCPConfigReq()
}

// ---------------- IPCP ----------------

func (s *Session) sendIPCPConfigReq() {
	var opts []byte
	ip := s.localIP
	if ip == nil {
		ip = net.IPv4(0, 0, 0, 0)
	}
	opts = append(opts, ipcpOption(ipcpOptIP, ip.To4())...)
	pri := s.priDNS
	if pri == nil {
		pri = net.IPv4(0, 0, 0, 0)
	}
	sec := s.secDNS
	if sec == nil {
		sec = net.IPv4(0, 0, 0, 0)
	}
	opts = append(opts, ipcpOption(ipcpOptPriDNS, pri.To4())...)
	opts = append(opts, ipcpOption(ipcpOptSecDNS, sec.To4())...)
	s.logf("IPCP: sending Configure-Request (id=%d, ip=%s)", s.ipcpID, ip)
	s.Send(encodeFrame(ProtoIPCP, encodeControl(CodeConfigureRequest, s.ipcpID, opts)))
}

func ipcpOption(t byte, v []byte) []byte {
	out := make([]byte, 2+len(v))
	out[0] = t
	out[1] = byte(2 + len(v))
	copy(out[2:], v)
	return out
}

func (s *Session) handleIPCP(p []byte) {
	if len(p) < 4 {
		return
	}
	code := p[0]
	id := p[1]
	length := int(binary.BigEndian.Uint16(p[2:4]))
	if length > len(p) {
		length = len(p)
	}
	data := p[4:length]

	switch code {
	case CodeConfigureRequest:
		// Ack whatever the peer wants for its own side.
		s.Send(encodeFrame(ProtoIPCP, encodeControl(CodeConfigureAck, id, data)))
	case CodeConfigureAck:
		if id == s.ipcpID {
			s.ipcpLocalAcked = true
			s.logf("IPCP: our Configure-Request acked")
			s.maybeIPCPUp()
		}
	case CodeConfigureNak:
		s.applyIPCPOptions(data)
		s.ipcpID++
		s.sendIPCPConfigReq()
	case CodeConfigureReject:
		// Remove rejected options (DNS) and retry with just the IP option.
		s.logf("IPCP: got Configure-Reject; retrying")
		s.ipcpID++
		var opts []byte
		ip := s.localIP
		if ip == nil {
			ip = net.IPv4(0, 0, 0, 0)
		}
		opts = append(opts, ipcpOption(ipcpOptIP, ip.To4())...)
		s.Send(encodeFrame(ProtoIPCP, encodeControl(CodeConfigureRequest, s.ipcpID, opts)))
	case CodeTerminateRequest:
		s.Send(encodeFrame(ProtoIPCP, encodeControl(CodeTerminateAck, id, nil)))
	}
}

func (s *Session) applyIPCPOptions(opts []byte) {
	i := 0
	for i+2 <= len(opts) {
		t := opts[i]
		l := int(opts[i+1])
		if l < 2 || i+l > len(opts) {
			break
		}
		v := opts[i+2 : i+l]
		switch t {
		case ipcpOptIP:
			if len(v) == 4 {
				s.localIP = net.IPv4(v[0], v[1], v[2], v[3])
			}
		case ipcpOptPriDNS:
			if len(v) == 4 {
				s.priDNS = net.IPv4(v[0], v[1], v[2], v[3])
			}
		case ipcpOptSecDNS:
			if len(v) == 4 {
				s.secDNS = net.IPv4(v[0], v[1], v[2], v[3])
			}
		}
		i += l
	}
	s.logf("IPCP: server assigned ip=%v priDNS=%v secDNS=%v", s.localIP, s.priDNS, s.secDNS)
}

func (s *Session) maybeIPCPUp() {
	if s.ph != phaseNetwork || !s.ipcpLocalAcked {
		return
	}
	s.ph = phaseUp
	cfg := NetConfig{LocalIP: s.localIP}
	if s.priDNS != nil {
		cfg.DNS = append(cfg.DNS, s.priDNS)
	}
	if s.secDNS != nil {
		cfg.DNS = append(cfg.DNS, s.secDNS)
	}
	s.logf("IPCP up; tunnel is ready (local IP %s)", s.localIP)
	if s.OnNetworkUp != nil {
		s.OnNetworkUp(cfg)
	}
}

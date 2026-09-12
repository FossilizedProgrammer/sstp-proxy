package ppp

import "encoding/binary"

// PPP protocol numbers.
const (
	ProtoLCP    = 0xC021
	ProtoPAP    = 0xC023
	ProtoCHAP   = 0xC223
	ProtoIPCP   = 0x8021
	ProtoIP     = 0x0021
	ProtoIPV6CP = 0x8057
	ProtoIPv6   = 0x0057
)

// PPP / LCP / IPCP control codes.
const (
	CodeConfigureRequest = 1
	CodeConfigureAck     = 2
	CodeConfigureNak     = 3
	CodeConfigureReject  = 4
	CodeTerminateRequest = 5
	CodeTerminateAck     = 6
	CodeCodeReject       = 7
	CodeProtocolReject   = 8
	CodeEchoRequest      = 9
	CodeEchoReply        = 10
	CodeDiscardRequest   = 11
)

// CHAP codes.
const (
	CHAPChallenge = 1
	CHAPResponse  = 2
	CHAPSuccess   = 3
	CHAPFailure   = 4
)

// PAP codes.
const (
	PAPAuthenticateRequest = 1
	PAPAuthenticateAck     = 2
	PAPAuthenticateNak     = 3
)

// LCP option types.
const (
	lcpOptMRU     = 1
	lcpOptAuth    = 3
	lcpOptMagic   = 5
	lcpOptPFC     = 7
	lcpOptACFC    = 8
)

// IPCP option types.
const (
	ipcpOptAddresses = 1
	ipcpOptIP        = 3
	ipcpOptPriDNS    = 129
	ipcpOptPriNBNS   = 130
	ipcpOptSecDNS    = 131
	ipcpOptSecNBNS   = 132
)

// CHAP auth algorithm identifiers.
const (
	chapAlgoMSCHAPv2 = 0x81
	chapAlgoMSCHAP   = 0x80
	chapAlgoMD5      = 0x05
)

// encodeFrame builds a PPP frame (with address/control field, no HDLC framing
// or byte-stuffing since SSTP runs over reliable TLS) for the given protocol.
func encodeFrame(proto uint16, payload []byte) []byte {
	out := make([]byte, 4+len(payload))
	out[0] = 0xFF
	out[1] = 0x03
	binary.BigEndian.PutUint16(out[2:4], proto)
	copy(out[4:], payload)
	return out
}

// decodeFrame strips the optional address/control field and returns the PPP
// protocol number plus the payload.
func decodeFrame(frame []byte) (proto uint16, payload []byte, ok bool) {
	i := 0
	if len(frame) >= 2 && frame[0] == 0xFF && frame[1] == 0x03 {
		i = 2
	}
	if len(frame) < i+1 {
		return 0, nil, false
	}
	// Protocol field may be 1 or 2 bytes (PFC). A protocol number is odd in
	// its least-significant byte; a single-byte proto has an odd value.
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

// encodeControl builds a PPP control packet (code, id, length, data).
func encodeControl(code, id byte, data []byte) []byte {
	out := make([]byte, 4+len(data))
	out[0] = code
	out[1] = id
	binary.BigEndian.PutUint16(out[2:4], uint16(4+len(data)))
	copy(out[4:], data)
	return out
}

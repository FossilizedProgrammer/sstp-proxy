package ppp

import (
	"crypto/des"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"

	"golang.org/x/crypto/md4"
)

// This file implements MS-CHAPv2 (RFC 2759) and the MPPE master-key derivation
// (RFC 3079) required to build the SSTP crypto-binding HLAK.

func utf16le(s string) []byte {
	out := make([]byte, 0, len(s)*2)
	for _, r := range s {
		out = append(out, byte(r), byte(r>>8))
	}
	return out
}

func ntPasswordHash(password string) []byte {
	h := md4.New()
	h.Write(utf16le(password))
	return h.Sum(nil) // 16 bytes
}

func ntPasswordHashHash(passwordHash []byte) []byte {
	h := md4.New()
	h.Write(passwordHash)
	return h.Sum(nil) // 16 bytes
}

// challengeHash computes the 8-byte challenge from peer/authenticator
// challenges and the user name (RFC 2759 8.2).
func challengeHash(peerChallenge, authChallenge []byte, username string) []byte {
	h := sha1.New()
	h.Write(peerChallenge)
	h.Write(authChallenge)
	h.Write([]byte(username))
	return h.Sum(nil)[:8]
}

// desEncrypt encrypts an 8-byte block with a 7-byte key expanded to 8 bytes
// with parity, as used by MS-CHAP.
func desEncrypt(key7, data8 []byte) []byte {
	key := make([]byte, 8)
	key[0] = key7[0]
	key[1] = key7[0]<<7 | key7[1]>>1
	key[2] = key7[1]<<6 | key7[2]>>2
	key[3] = key7[2]<<5 | key7[3]>>3
	key[4] = key7[3]<<4 | key7[4]>>4
	key[5] = key7[4]<<3 | key7[5]>>5
	key[6] = key7[5]<<2 | key7[6]>>6
	key[7] = key7[6] << 1
	// set parity (least significant bit) — DES ignores it but be tidy.
	for i := range key {
		key[i] &= 0xFE
	}
	block, _ := des.NewCipher(key)
	out := make([]byte, 8)
	block.Encrypt(out, data8)
	return out
}

// challengeResponse computes the 24-byte NT response (RFC 2759 8.5).
func challengeResponse(challenge8, passwordHash []byte) []byte {
	zpwd := make([]byte, 21)
	copy(zpwd, passwordHash)
	resp := make([]byte, 0, 24)
	resp = append(resp, desEncrypt(zpwd[0:7], challenge8)...)
	resp = append(resp, desEncrypt(zpwd[7:14], challenge8)...)
	resp = append(resp, desEncrypt(zpwd[14:21], challenge8)...)
	return resp
}

// mschapv2 holds the artefacts produced by an MS-CHAPv2 exchange.
type mschapv2 struct {
	PeerChallenge []byte
	NTResponse    []byte
	AuthChallenge []byte
	Username      string
	Password      string
}

// buildResponse returns the 49-byte MS-CHAPv2 response value:
// PeerChallenge(16) + Reserved(8) + NTResponse(24) + Flags(1).
func newMSCHAPv2(username, password string, authChallenge []byte) *mschapv2 {
	peer := make([]byte, 16)
	_, _ = rand.Read(peer)
	pwdHash := ntPasswordHash(password)
	chal := challengeHash(peer, authChallenge, username)
	nt := challengeResponse(chal, pwdHash)
	return &mschapv2{
		PeerChallenge: peer,
		NTResponse:    nt,
		AuthChallenge: authChallenge,
		Username:      username,
		Password:      password,
	}
}

func (m *mschapv2) responseValue() []byte {
	v := make([]byte, 49)
	copy(v[0:16], m.PeerChallenge)
	// 8 reserved zero bytes
	copy(v[24:48], m.NTResponse)
	v[48] = 0
	return v
}

// --- MPPE / HLAK derivation (RFC 3079) ---

var (
	magic1 = []byte("This is the MPPE Master Key")
	magic2 = []byte("On the client side, this is the send key; " +
		"on the server side, it is the receive key.")
	magic3 = []byte("On the client side, this is the receive key; " +
		"on the server side, it is the send key.")
	shsPad1 = make([]byte, 40)                    // 40 x 0x00
	shsPad2 = bytesRepeat(0xF2, 40)               // 40 x 0xF2
)

func bytesRepeat(b byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}

func getMasterKey(passwordHashHash, ntResponse []byte) []byte {
	h := sha1.New()
	h.Write(passwordHashHash)
	h.Write(ntResponse)
	h.Write(magic1)
	return h.Sum(nil)[:16]
}

func getAsymmetricStartKey(masterKey []byte, isSend bool) []byte {
	var s []byte
	// Client perspective: send key uses magic2, receive key uses magic3.
	if isSend {
		s = magic2
	} else {
		s = magic3
	}
	h := sha1.New()
	h.Write(masterKey)
	h.Write(shsPad1)
	h.Write(s)
	h.Write(shsPad2)
	return h.Sum(nil)[:16]
}

// HLAK returns the 32-byte Higher-Layer Authentication Key for the SSTP crypto
// binding: for the client HLAK = MasterSendKey | MasterReceiveKey.
func (m *mschapv2) HLAK() []byte {
	pwdHash := ntPasswordHash(m.Password)
	pwdHashHash := ntPasswordHashHash(pwdHash)
	masterKey := getMasterKey(pwdHashHash, m.NTResponse)
	sendKey := getAsymmetricStartKey(masterKey, true)
	recvKey := getAsymmetricStartKey(masterKey, false)
	out := make([]byte, 0, 32)
	out = append(out, sendKey...)
	out = append(out, recvKey...)
	return out
}

// ServerComputeClientHLAK reconstructs the SSTP client's 32-byte HLAK on the
// server side, given the account password and the 24-byte NT-Response the
// client sent in its MS-CHAPv2 reply. For MS-CHAPv2 the client HLAK
// (MasterSendKey|MasterReceiveKey) and the server HLAK
// (MasterReceiveKey|MasterSendKey) are byte-identical because the direction
// naming compensates for the reversed perspective, so the same value validates
// the crypto-binding Compound MAC. Exposed for server implementations / tests.
func ServerComputeClientHLAK(password string, ntResponse []byte) []byte {
	pwdHash := ntPasswordHash(password)
	pwdHashHash := ntPasswordHashHash(pwdHash)
	masterKey := getMasterKey(pwdHashHash, ntResponse)
	sendKey := getAsymmetricStartKey(masterKey, true)
	recvKey := getAsymmetricStartKey(masterKey, false)
	out := make([]byte, 0, 32)
	out = append(out, sendKey...)
	out = append(out, recvKey...)
	return out
}

// ensure md5 import is used (some builds strip it otherwise); MD5 is available
// for CHAP-MD5 fallback response generation.
func chapMD5Response(id byte, password string, challenge []byte) []byte {
	h := md5.New()
	h.Write([]byte{id})
	h.Write([]byte(password))
	h.Write(challenge)
	return h.Sum(nil)
}

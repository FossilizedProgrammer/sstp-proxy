package ppp

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"hash"
)

// cmkSeed is the 29-byte ASCII seed defined by [MS-SSTP] 3.2.5.2.2.
var cmkSeed = []byte("SSTP inner method derived CMK")

// ComputeCMK derives the Compound MAC Key from the HLAK using the IKEv2 PRF+
// construction described in [MS-SSTP]. sha256 selects HMAC-SHA256-256 (32-byte
// CMK) versus HMAC-SHA1-160 (20-byte CMK).
func ComputeCMK(hlak []byte, useSHA256 bool) []byte {
	var newHash func() hash.Hash
	var outLen int
	if useSHA256 {
		newHash = sha256.New
		outLen = 32
	} else {
		newHash = sha1.New
		outLen = 20
	}
	// PRF+(K, S, LEN): T1 = HMAC(K, S | LEN_LE16 | 0x01). One iteration is
	// enough because HMAC output already equals the requested length.
	lenLE := make([]byte, 2)
	binary.LittleEndian.PutUint16(lenLE, uint16(outLen))
	mac := hmac.New(newHash, hlak)
	mac.Write(cmkSeed)
	mac.Write(lenLE)
	mac.Write([]byte{0x01})
	return mac.Sum(nil)[:outLen]
}

// ComputeCMAC computes the Compound MAC over the full CALL_CONNECTED message
// (with the MAC field already zeroed) keyed by the CMK.
func ComputeCMAC(cmk, message []byte, useSHA256 bool) []byte {
	var newHash func() hash.Hash
	if useSHA256 {
		newHash = sha256.New
	} else {
		newHash = sha1.New
	}
	mac := hmac.New(newHash, cmk)
	mac.Write(message)
	return mac.Sum(nil)
}

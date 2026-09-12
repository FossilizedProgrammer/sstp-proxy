package sstp

import (
	"crypto/rand"
	"encoding/hex"
	"strings"
)

// newGUID returns an upper-case random GUID string of the form
// XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX used for the SSTP correlation id.
func newGUID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // variant
	h := hex.EncodeToString(b[:])
	var sb strings.Builder
	sb.WriteString(h[0:8])
	sb.WriteByte('-')
	sb.WriteString(h[8:12])
	sb.WriteByte('-')
	sb.WriteString(h[12:16])
	sb.WriteByte('-')
	sb.WriteString(h[16:20])
	sb.WriteByte('-')
	sb.WriteString(h[20:32])
	return strings.ToUpper(sb.String())
}

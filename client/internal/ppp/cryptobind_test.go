package ppp

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"
)

func unhex(s string) []byte {
	s = strings.Join(strings.Fields(s), "")
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

// Vectors taken directly from [MS-SSTP] section 4.7 "Crypto Binding".
func TestCryptoBindingSHA256(t *testing.T) {
	hlak := unhex(`2A 1B B4 0D 55 AB 0F 5E F3 2F 06 F2 B3 CC 73 C4
		8F D3 FA C4 1D 7A 13 15 A1 92 28 D9 02 4C A1 64`)
	msg := unhex(`10 01 00 70 00 04 00 01 00 03 00 68 00 00 00 02
		41 2B 48 9A EB D7 EC C7 D0 89 66 F2 6B E7 CD 72
		B2 31 A0 E9 21 0D 7C 91 B3 08 86 2B 03 44 C4 35
		79 93 EF 31 4C 49 3D AC E9 F0 2D 60 E7 E6 1C 84
		B6 69 0A AF E9 D7 AE EA 92 CB BE 8A D5 99 42 2D
		52 A6 8E FD 8C FF BF 52 77 0B 8F 0F E8 EC 73 71
		65 83 AF 6D 61 1E B6 D1 79 B3 B2 08 40 98 54 49`)
	want := unhex(`52 A6 8E FD 8C FF BF 52 77 0B 8F 0F E8 EC 73 71
		65 83 AF 6D 61 1E B6 D1 79 B3 B2 08 40 98 54 49`)

	// Zero the MAC field (offset 80, 32 bytes) before computing.
	zeroed := append([]byte{}, msg...)
	for i := 80; i < 112; i++ {
		zeroed[i] = 0
	}
	cmk := ComputeCMK(hlak, true)
	got := ComputeCMAC(cmk, zeroed, true)
	if !bytes.Equal(got, want) {
		t.Fatalf("SHA256 CMAC mismatch\n got=%x\nwant=%x", got, want)
	}
}

func TestCryptoBindingSHA1(t *testing.T) {
	hlak := unhex(`4B 31 28 F4 39 25 D9 00 6E EF B1 C4 E8 65 15 A1
		D8 8E 56 BA B3 CA 2B DF 03 73 B7 F5 A8 A1 3B 19`)
	msg := unhex(`10 01 00 70 00 04 00 01 00 03 00 68 00 00 00 01
		0F 1A 2D 58 D4 A3 E3 00 0F AD 3C E4 90 6E 07 B7
		07 AA 9E 44 1C CE AC 5C BD 7B 2C C1 C9 D8 6C DF
		58 26 B6 29 BD A5 9B 8E 6F D8 DC D2 62 2F D3 4C
		53 48 05 A5 00 00 00 00 00 00 00 00 00 00 00 00
		69 91 5D D5 83 D8 06 2F EF 16 F6 1D B2 F0 32 90
		EC 27 CB 6C 00 00 00 00 00 00 00 00 00 00 00 00`)
	want := unhex(`69 91 5D D5 83 D8 06 2F EF 16 F6 1D B2 F0 32 90
		EC 27 CB 6C`)

	zeroed := append([]byte{}, msg...)
	for i := 80; i < 112; i++ {
		zeroed[i] = 0
	}
	cmk := ComputeCMK(hlak, false)
	got := ComputeCMAC(cmk, zeroed, false)
	if !bytes.Equal(got, want) {
		t.Fatalf("SHA1 CMAC mismatch\n got=%x\nwant=%x", got, want)
	}
}

package ppp

import (
	"bytes"
	"testing"
)

// Test vectors from RFC 2759 section 9.2 (MS-CHAP-V2 examples).
func TestMSCHAPv2Vectors(t *testing.T) {
	username := "User"
	password := "clientPass"
	authChallenge := unhex("5B 5D 7C 7D 7B 3F 2F 3E 3C 2C 60 21 32 26 26 28")
	peerChallenge := unhex("21 40 23 24 25 5E 26 2A 28 29 5F 2B 3A 33 7C 7E")

	if got, want := ntPasswordHash(password), unhex("44 EB BA 8D 53 12 B8 D6 11 47 44 11 F5 69 89 AE"); !bytes.Equal(got, want) {
		t.Fatalf("PasswordHash mismatch\n got=%x\nwant=%x", got, want)
	}
	if got, want := ntPasswordHashHash(ntPasswordHash(password)), unhex("41 C0 0C 58 4B D2 D9 1C 40 17 A2 A1 2F A5 9F 3F"); !bytes.Equal(got, want) {
		t.Fatalf("PasswordHashHash mismatch\n got=%x\nwant=%x", got, want)
	}

	chal := challengeHash(peerChallenge, authChallenge, username)
	if got, want := chal, unhex("D0 2E 43 86 BC E9 12 26"); !bytes.Equal(got, want) {
		t.Fatalf("Challenge mismatch\n got=%x\nwant=%x", got, want)
	}

	nt := challengeResponse(chal, ntPasswordHash(password))
	want := unhex("82 30 9E CD 8D 70 8B 5E A0 8F AA 39 81 CD 83 54 42 33 11 4A 3D 85 D6 DF")
	if !bytes.Equal(nt, want) {
		t.Fatalf("NT-Response mismatch\n got=%x\nwant=%x", nt, want)
	}
}

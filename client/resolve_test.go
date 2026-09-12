package main

import "testing"

func TestResolveServerAddr(t *testing.T) {
	cases := []struct {
		server  string
		port    int
		want    string
		wantErr bool
	}{
		{"public-vpn-124.opengw.net", 443, "public-vpn-124.opengw.net:443", false},
		{"vpn258563631.opengw.net", 1423, "vpn258563631.opengw.net:1423", false},
		{"vpn258563631.opengw.net:1423", 443, "vpn258563631.opengw.net:1423", false}, // :port wins
		{"219.100.37.12", 443, "219.100.37.12:443", false},
		{"219.100.37.12:992", 443, "219.100.37.12:992", false},
		{"https://vpn.example.com/", 443, "vpn.example.com:443", false},
		{"https://vpn.example.com:1720", 443, "vpn.example.com:1720", false},
		{"::1", 8443, "[::1]:8443", false},
		{"[2001:db8::1]:1194", 443, "[2001:db8::1]:1194", false},
		{"", 443, "", true},
		{"host", 0, "", true},
		{"host:99999", 443, "", true},
	}
	for _, c := range cases {
		got, err := resolveServerAddr(c.server, c.port)
		if c.wantErr {
			if err == nil {
				t.Errorf("resolveServerAddr(%q,%d) expected error, got %q", c.server, c.port, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("resolveServerAddr(%q,%d) unexpected error: %v", c.server, c.port, err)
			continue
		}
		if got != c.want {
			t.Errorf("resolveServerAddr(%q,%d) = %q, want %q", c.server, c.port, got, c.want)
		}
	}
}

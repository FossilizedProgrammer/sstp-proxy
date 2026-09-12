package upstream

import (
	"testing"
	"time"
)

func TestFromURL(t *testing.T) {
	cases := []struct {
		url     string
		wantErr bool
	}{
		{"", false},                              // direct
		{"socks5://127.0.0.1:1080", false},
		{"socks5h://user:pass@127.0.0.1:1080", false},
		{"http://127.0.0.1:8080", false},
		{"http://user:pass@10.0.0.1:3128", false},
		{"https://proxy.example.com:443", false},
		{"ftp://127.0.0.1:21", true},             // unsupported scheme
		{"://bad", true},                          // invalid URL
	}
	for _, c := range cases {
		d, err := FromURL(c.url, 5*time.Second)
		if c.wantErr {
			if err == nil {
				t.Errorf("FromURL(%q) expected error, got nil", c.url)
			}
			continue
		}
		if err != nil {
			t.Errorf("FromURL(%q) unexpected error: %v", c.url, err)
			continue
		}
		if d == nil {
			t.Errorf("FromURL(%q) returned nil dialer", c.url)
		}
	}
}

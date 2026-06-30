package internal

import (
	"strings"
	"testing"
)

func TestProxyValidation(t *testing.T) {
	cases := []struct {
		name    string
		args    []string
		wantErr string
	}{
		{"P https rejected", []string{"client", "-s", "h:1", "-k", "k", "-P", "https://proxy:443"}, "unsupported -P scheme"},
		{"P ftp rejected", []string{"client", "-s", "h:1", "-k", "k", "-P", "ftp://proxy:21"}, "unsupported -P scheme"},
		{"E https rejected", []string{"server", "-k", "k", "-E", "https://proxy:443"}, "unsupported -E scheme"},
		{"U without P or E", []string{"client", "-s", "h:1", "-k", "k", "-U", "u:p"}, "requires -P or -E"},
		{"U with socks5 P only", []string{"client", "-s", "h:1", "-k", "k", "-P", "socks5://h:1", "-U", "u:p"}, "requires an http://"},
		{"U with socks5 E only", []string{"server", "-k", "k", "-E", "socks5://h:1", "-U", "u:p"}, "requires an http://"},
		{"U no colon", []string{"client", "-s", "h:1", "-k", "k", "-P", "http://h:1", "-U", "alicebadformat"}, "user:pass"},
		{"valid P http + U", []string{"client", "-s", "h:1", "-k", "k", "-P", "http://h:1", "-U", "u:p"}, ""},
		{"valid E http + U (server)", []string{"server", "-k", "k", "-E", "http://h:1", "-U", "u:p"}, ""},
		{"valid E socks5 no U (server)", []string{"server", "-k", "k", "-E", "socks5://h:1"}, ""},
		{"valid P + E both http + U shared", []string{"reverse", "-r", "1080", "-s", "h:1", "-k", "k", "-P", "http://h:1", "-E", "http://h:2", "-U", "u:p"}, ""},
		{"valid special chars", []string{"client", "-s", "h:1", "-k", "k", "-P", "http://h:1", "-U", "u:p@ss:w0rd"}, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := Parse(c.args)
			if c.wantErr == "" {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				return
			}
			if err == nil {
				t.Errorf("expected error containing %q, got nil", c.wantErr)
				return
			}
			if !strings.Contains(err.Error(), c.wantErr) {
				t.Errorf("error %q does not contain %q", err.Error(), c.wantErr)
			}
		})
	}
}

package internal

import (
	"strings"
	"testing"
)

func TestProxyAuthValidation(t *testing.T) {
	cases := []struct {
		name    string
		args    []string
		wantErr string
	}{
		{"no colon", []string{"client", "-s", "h:1", "-k", "k", "-P", "http://h:1", "-U", "alicebadformat"}, "user:pass"},
		{"U without P", []string{"client", "-s", "h:1", "-k", "k", "-U", "u:p"}, "requires proxy URL"},
		{"U with socks5", []string{"client", "-s", "h:1", "-k", "k", "-P", "socks5://h:1", "-U", "u:p"}, "only supported with http"},
		{"valid", []string{"client", "-s", "h:1", "-k", "k", "-P", "http://h:1", "-U", "u:p"}, ""},
		{"valid with special chars", []string{"client", "-s", "h:1", "-k", "k", "-P", "http://h:1", "-U", "u:p@ss:w0rd"}, ""},
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

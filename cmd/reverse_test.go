package cmd

import "testing"

func TestParseReverseSpecProxyDefault(t *testing.T) {
	bind, port, target, isProxy, err := parseReverseSpec("1080")
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if bind != "127.0.0.1" {
		t.Errorf("bind: got %q, want 127.0.0.1", bind)
	}
	if port != 1080 {
		t.Errorf("port: got %d, want 1080", port)
	}
	if target != "" {
		t.Errorf("target: got %q, want empty", target)
	}
	if !isProxy {
		t.Error("expected proxy mode")
	}
}

func TestParseReverseSpecProxyAllInterfaces(t *testing.T) {
	bind, _, _, isProxy, err := parseReverseSpec(":1080")
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if bind != "0.0.0.0" {
		t.Errorf("bind: got %q, want 0.0.0.0", bind)
	}
	if !isProxy {
		t.Error("expected proxy mode")
	}
}

func TestParseReverseSpecFixedDefault(t *testing.T) {
	bind, port, target, isProxy, err := parseReverseSpec("3306:10.0.0.5:3306")
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if bind != "127.0.0.1" {
		t.Errorf("bind: got %q, want 127.0.0.1", bind)
	}
	if port != 3306 {
		t.Errorf("port: got %d, want 3306", port)
	}
	if target != "10.0.0.5:3306" {
		t.Errorf("target: got %q", target)
	}
	if isProxy {
		t.Error("expected fixed target mode")
	}
}

func TestParseReverseSpecFixedAllInterfaces(t *testing.T) {
	bind, _, target, isProxy, err := parseReverseSpec(":3306:10.0.0.5:3306")
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if bind != "0.0.0.0" {
		t.Errorf("bind: got %q, want 0.0.0.0", bind)
	}
	if target != "10.0.0.5:3306" {
		t.Errorf("target: got %q", target)
	}
	if isProxy {
		t.Error("expected fixed target mode")
	}
}

func TestParseReverseSpecDomainTarget(t *testing.T) {
	_, _, target, _, err := parseReverseSpec("8080:internal-api.corp:80")
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if target != "internal-api.corp:80" {
		t.Errorf("target: got %q", target)
	}
}

func TestParseReverseSpecInvalidPort(t *testing.T) {
	_, _, _, _, err := parseReverseSpec("abc")
	if err == nil {
		t.Fatal("expected error for invalid port")
	}
}

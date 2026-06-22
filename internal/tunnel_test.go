package internal

import (
	"bytes"
	"net"
	"testing"
)

func TestFrameRoundTripIPv4(t *testing.T) {
	key := DeriveKey("test-key")

	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	original := &Frame{
		Atyp: 0x01,
		Addr: net.IPv4(192, 168, 1, 1),
		Port: 8080,
		Data: []byte("payload data"),
	}

	done := make(chan struct{})
	go func() {
		WriteFrame(client, key, original)
		close(done)
	}()

	received, err := ReadFrame(server, key)
	if err != nil {
		t.Fatalf("ReadFrame failed: %v", err)
	}

	if received.Port != original.Port {
		t.Errorf("port mismatch: got %d, want %d", received.Port, original.Port)
	}
	if !bytes.Equal(received.Data, original.Data) {
		t.Errorf("data mismatch: got %q, want %q", received.Data, original.Data)
	}
	<-done
}

func TestFrameRoundTripDomain(t *testing.T) {
	key := DeriveKey("test-key")

	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	original := &Frame{
		Atyp: 0x03,
		Addr: []byte("example.com"),
		Port: 443,
		Data: []byte("https request"),
	}

	done := make(chan struct{})
	go func() {
		WriteFrame(client, key, original)
		close(done)
	}()

	received, err := ReadFrame(server, key)
	if err != nil {
		t.Fatalf("ReadFrame failed: %v", err)
	}

	if string(received.Addr) != "example.com" {
		t.Errorf("domain mismatch: got %q", string(received.Addr))
	}
	if received.Port != 443 {
		t.Errorf("port mismatch: got %d", received.Port)
	}
	<-done
}

func TestFrameEmptyData(t *testing.T) {
	key := DeriveKey("k")

	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	original := &Frame{
		Atyp: 0x01,
		Addr: net.IPv4(10, 0, 0, 1),
		Port: 3306,
		Data: nil,
	}

	done := make(chan struct{})
	go func() {
		WriteFrame(client, key, original)
		close(done)
	}()

	received, err := ReadFrame(server, key)
	if err != nil {
		t.Fatalf("ReadFrame: %v", err)
	}
	if len(received.Data) != 0 {
		t.Errorf("expected empty data, got %d bytes", len(received.Data))
	}
	<-done
}

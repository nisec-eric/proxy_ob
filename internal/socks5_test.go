package internal

import (
	"bytes"
	"net"
	"testing"
)

func TestSOCKS5HandshakeSuccess(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	done := make(chan error, 1)
	go func() {
		done <- Handshake(server)
	}()

	client.Write([]byte{0x05, 0x01, 0x00})

	reply := make([]byte, 2)
	client.Read(reply)

	if reply[0] != 0x05 || reply[1] != 0x00 {
		t.Fatalf("expected [0x05, 0x00], got %v", reply)
	}

	if err := <-done; err != nil {
		t.Fatalf("Handshake failed: %v", err)
	}
}

func TestSOCKS5ReadRequestIPv4(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	done := make(chan struct {
		addr string
		port uint16
		err  error
	}, 1)

	go func() {
		addr, port, _, err := ReadRequest(server)
		done <- struct {
			addr string
			port uint16
			err  error
		}{addr, port, err}
	}()

	client.Write([]byte{
		0x05, 0x01, 0x00, 0x01,
		192, 168, 1, 1,
		0x1F, 0x90,
	})

	result := <-done
	if result.err != nil {
		t.Fatalf("ReadRequest: %v", result.err)
	}
	if result.addr != "192.168.1.1" {
		t.Errorf("addr: got %q, want 192.168.1.1", result.addr)
	}
	if result.port != 8080 {
		t.Errorf("port: got %d, want 8080", result.port)
	}
}

func TestSOCKS5ReadRequestDomain(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	done := make(chan struct {
		addr string
		port uint16
		err  error
	}, 1)

	go func() {
		addr, port, _, err := ReadRequest(server)
		done <- struct {
			addr string
			port uint16
			err  error
		}{addr, port, err}
	}()

	domain := "example.com"
	client.Write([]byte{
		0x05, 0x01, 0x00, 0x03,
		byte(len(domain)),
	})
	client.Write([]byte(domain))
	client.Write([]byte{0x01, 0xBB})

	result := <-done
	if result.err != nil {
		t.Fatalf("ReadRequest: %v", result.err)
	}
	if result.addr != "example.com" {
		t.Errorf("addr: got %q", result.addr)
	}
	if result.port != 443 {
		t.Errorf("port: got %d, want 443", result.port)
	}
}

func TestSOCKS5SendReply(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	go func() {
		SendReply(server, ReplySucceeded)
	}()

	reply := make([]byte, 10)
	client.Read(reply)

	expected := []byte{0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	if !bytes.Equal(reply, expected) {
		t.Errorf("reply mismatch: got %v, want %v", reply, expected)
	}
}

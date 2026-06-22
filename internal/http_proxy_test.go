package internal

import (
	"bufio"
	"bytes"
	"net"
	"strings"
	"testing"
	"time"
)

func TestReadHTTPProxyRequestCONNECT(t *testing.T) {
	req := "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com\r\n\r\n"
	br := bufio.NewReader(strings.NewReader(req))

	host, port, isConnect, data, err := ReadHTTPProxyRequest(br)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if host != "example.com" {
		t.Errorf("host: got %q, want example.com", host)
	}
	if port != 443 {
		t.Errorf("port: got %d, want 443", port)
	}
	if !isConnect {
		t.Error("expected CONNECT method")
	}
	if data != nil {
		t.Error("CONNECT should have nil initial data")
	}
}

func TestReadHTTPProxyRequestPlainHTTP(t *testing.T) {
	req := "GET http://example.com/path HTTP/1.1\r\nHost: example.com\r\n\r\n"
	br := bufio.NewReader(strings.NewReader(req))

	host, port, isConnect, data, err := ReadHTTPProxyRequest(br)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if host != "example.com" {
		t.Errorf("host: got %q", host)
	}
	if port != 80 {
		t.Errorf("port: got %d, want 80", port)
	}
	if isConnect {
		t.Error("expected non-CONNECT method")
	}
	if !bytes.Contains(data, []byte("GET /path HTTP/1.1")) {
		t.Errorf("rewritten request should have relative URI, got %q", data)
	}
}

func TestReadHTTPProxyRequestMalformed(t *testing.T) {
	req := "INVALID REQUEST\r\n\r\n"
	br := bufio.NewReader(strings.NewReader(req))

	_, _, _, _, err := ReadHTTPProxyRequest(br)
	if err == nil {
		t.Fatal("expected error for malformed request")
	}
}

func TestSendHTTPResponse(t *testing.T) {
	var buf bytes.Buffer
	conn := &mockConn{buf: &buf}

	SendHTTPResponse(conn, 200, "Connection established")

	output := buf.String()
	if !strings.HasPrefix(output, "HTTP/1.1 200") {
		t.Errorf("unexpected response: %q", output)
	}
	if !strings.HasSuffix(output, "\r\n\r\n") {
		t.Errorf("response should end with CRLF CRLF")
	}
}

type mockConn struct {
	buf *bytes.Buffer
}

func (m *mockConn) Read(b []byte) (int, error)          { return m.buf.Read(b) }
func (m *mockConn) Write(b []byte) (int, error)         { return m.buf.Write(b) }
func (m *mockConn) Close() error                        { return nil }
func (m *mockConn) LocalAddr() net.Addr                 { return nil }
func (m *mockConn) RemoteAddr() net.Addr                { return nil }
func (m *mockConn) SetDeadline(t time.Time) error       { return nil }
func (m *mockConn) SetReadDeadline(t time.Time) error   { return nil }
func (m *mockConn) SetWriteDeadline(t time.Time) error  { return nil }

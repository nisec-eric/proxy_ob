package internal

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// DialThroughProxy dials target through an upstream proxy.
// proxyURL scheme must be http:// or socks5://.
// proxyAuth is "user:pass" for HTTP Basic auth (ignored by SOCKS5).
func DialThroughProxy(proxyURL, proxyAuth, target string, timeout time.Duration) (net.Conn, error) {
	u, err := url.Parse(proxyURL)
	if err != nil {
		return nil, fmt.Errorf("parse proxy url: %w", err)
	}
	switch u.Scheme {
	case "http":
		return dialHTTPConnect(u.Host, proxyAuth, target, timeout)
	case "socks5", "socks5h", "socks":
		return dialSOCKS5(u.Host, target, timeout)
	default:
		return nil, fmt.Errorf("unsupported proxy scheme %q: use http:// or socks5://", u.Scheme)
	}
}

type bufferedConn struct {
	*bufio.Reader
	net.Conn
}

func (b *bufferedConn) Read(p []byte) (int, error) { return b.Reader.Read(p) }

func dialHTTPConnect(proxyAddr, proxyAuth, target string, timeout time.Duration) (net.Conn, error) {
	if proxyAddr == "" {
		proxyAddr = "80"
	}
	if _, _, err := net.SplitHostPort(proxyAddr); err != nil {
		proxyAddr = net.JoinHostPort(proxyAddr, "80")
	}

	conn, err := net.DialTimeout("tcp", proxyAddr, timeout)
	if err != nil {
		return nil, fmt.Errorf("dial http proxy: %w", err)
	}

	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		conn.Close()
		return nil, fmt.Errorf("set deadline: %w", err)
	}

	var sb strings.Builder
	fmt.Fprintf(&sb, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n", target, target)
	if proxyAuth != "" {
		cred := base64.StdEncoding.EncodeToString([]byte(proxyAuth))
		fmt.Fprintf(&sb, "Proxy-Authorization: Basic %s\r\n", cred)
	}
	sb.WriteString("\r\n")

	if _, err := conn.Write([]byte(sb.String())); err != nil {
		conn.Close()
		return nil, fmt.Errorf("send CONNECT: %w", err)
	}

	br := bufio.NewReader(conn)
	statusLine, err := br.ReadString('\n')
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("read CONNECT status: %w", err)
	}

	fields := strings.Fields(statusLine)
	if len(fields) < 2 || !strings.HasPrefix(fields[0], "HTTP/") {
		conn.Close()
		return nil, fmt.Errorf("malformed CONNECT status: %q", statusLine)
	}
	code, err := strconv.Atoi(fields[1])
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("parse CONNECT status code from %q: %w", statusLine, err)
	}

	if code != 200 {
		conn.Close()
		return nil, fmt.Errorf("CONNECT failed: %s", strings.TrimSpace(statusLine))
	}

	for {
		line, err := br.ReadString('\n')
		if err != nil {
			conn.Close()
			return nil, fmt.Errorf("read CONNECT headers: %w", err)
		}
		if line == "\r\n" || line == "\n" {
			break
		}
	}

	if err := conn.SetDeadline(time.Time{}); err != nil {
		conn.Close()
		return nil, fmt.Errorf("clear deadline: %w", err)
	}

	return &bufferedConn{br, conn}, nil
}

func dialSOCKS5(proxyAddr, target string, timeout time.Duration) (net.Conn, error) {
	if _, _, err := net.SplitHostPort(proxyAddr); err != nil {
		proxyAddr = net.JoinHostPort(proxyAddr, "1080")
	}

	conn, err := net.DialTimeout("tcp", proxyAddr, timeout)
	if err != nil {
		return nil, fmt.Errorf("dial socks5 proxy: %w", err)
	}

	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		conn.Close()
		return nil, fmt.Errorf("set deadline: %w", err)
	}

	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		conn.Close()
		return nil, fmt.Errorf("socks5 greeting: %w", err)
	}

	greeting := make([]byte, 2)
	if _, err := io.ReadFull(conn, greeting); err != nil {
		conn.Close()
		return nil, fmt.Errorf("socks5 greeting response: %w", err)
	}
	if greeting[0] != 0x05 {
		conn.Close()
		return nil, fmt.Errorf("socks5 invalid version %d", greeting[0])
	}
	if greeting[1] != 0x00 {
		conn.Close()
		return nil, fmt.Errorf("socks5 requires auth (method 0x%02x), not supported", greeting[1])
	}

	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("split target: %w", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 0 || port > 65535 {
		conn.Close()
		return nil, fmt.Errorf("invalid port %q", portStr)
	}

	req := []byte{0x05, 0x01, 0x00}
	if ip := net.ParseIP(host); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			req = append(req, 0x01)
			req = append(req, ip4...)
		} else {
			req = append(req, 0x04)
			req = append(req, ip.To16()...)
		}
	} else {
		req = append(req, 0x03, byte(len(host)))
		req = append(req, []byte(host)...)
	}
	req = append(req, byte(port>>8), byte(port))

	if _, err := conn.Write(req); err != nil {
		conn.Close()
		return nil, fmt.Errorf("socks5 connect request: %w", err)
	}

	reply := make([]byte, 4)
	if _, err := io.ReadFull(conn, reply); err != nil {
		conn.Close()
		return nil, fmt.Errorf("socks5 reply: %w", err)
	}
	if reply[1] != 0x00 {
		conn.Close()
		return nil, fmt.Errorf("socks5 connect failed: code 0x%02x", reply[1])
	}

	var skip int
	switch reply[3] {
	case 0x01:
		skip = 4
	case 0x03:
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			conn.Close()
			return nil, fmt.Errorf("socks5 reply domain length: %w", err)
		}
		skip = int(lenBuf[0])
	case 0x04:
		skip = 16
	}
	if skip > 0 {
		if _, err := io.ReadFull(conn, make([]byte, skip)); err != nil {
			conn.Close()
			return nil, fmt.Errorf("socks5 reply addr: %w", err)
		}
	}
	if _, err := io.ReadFull(conn, make([]byte, 2)); err != nil {
		conn.Close()
		return nil, fmt.Errorf("socks5 reply port: %w", err)
	}

	if err := conn.SetDeadline(time.Time{}); err != nil {
		conn.Close()
		return nil, fmt.Errorf("clear deadline: %w", err)
	}

	return conn, nil
}

package internal

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
)

// SOCKS5 reply codes.
const (
	ReplySucceeded           byte = 0x00
	ReplyGeneralFailure      byte = 0x01
	ReplyNetworkUnreachable  byte = 0x03
	ReplyHostUnreachable     byte = 0x04
	ReplyConnectionRefused   byte = 0x05
	ReplyCommandNotSupported byte = 0x07
	ReplyAddrNotSupported    byte = 0x08
)

// Handshake performs the SOCKS5 handshake, accepting only NO AUTH (0x00).
func Handshake(conn net.Conn) error {
	buf := make([]byte, 2)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return fmt.Errorf("reading socks5 greeting: %w", err)
	}
	if buf[0] != 0x05 {
		return fmt.Errorf("not SOCKS5: version 0x%02x", buf[0])
	}
	nmethods := int(buf[1])
	methods := make([]byte, nmethods)
	if _, err := io.ReadFull(conn, methods); err != nil {
		return fmt.Errorf("reading methods: %w", err)
	}
	for _, m := range methods {
		if m == 0x00 {
			_, err := conn.Write([]byte{0x05, 0x00})
			return err
		}
	}
	conn.Write([]byte{0x05, 0xFF})
	return fmt.Errorf("no acceptable auth method")
}

// ReadRequest reads a SOCKS5 connect request and returns the target address, port, and address type.
func ReadRequest(conn net.Conn) (addr string, port uint16, atyp byte, err error) {
	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return "", 0, 0, fmt.Errorf("reading request header: %w", err)
	}
	if header[0] != 0x05 {
		return "", 0, 0, fmt.Errorf("not SOCKS5: version 0x%02x", header[0])
	}
	cmd := header[1]
	atyp = header[3]

	if cmd != 0x01 {
		SendReply(conn, ReplyCommandNotSupported)
		return "", 0, 0, fmt.Errorf("command not supported: 0x%02x", cmd)
	}

	switch atyp {
	case 0x01: // IPv4
		ip := make([]byte, 4)
		if _, err := io.ReadFull(conn, ip); err != nil {
			return "", 0, 0, fmt.Errorf("reading IPv4 address: %w", err)
		}
		addr = net.IP(ip).String()
	case 0x03: // Domain
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			return "", 0, 0, fmt.Errorf("reading domain length: %w", err)
		}
		domain := make([]byte, lenBuf[0])
		if _, err := io.ReadFull(conn, domain); err != nil {
			return "", 0, 0, fmt.Errorf("reading domain: %w", err)
		}
		addr = string(domain)
	case 0x04: // IPv6
		ip := make([]byte, 16)
		if _, err := io.ReadFull(conn, ip); err != nil {
			return "", 0, 0, fmt.Errorf("reading IPv6 address: %w", err)
		}
		addr = net.IP(ip).String()
	default:
		SendReply(conn, ReplyAddrNotSupported)
		return "", 0, 0, fmt.Errorf("unsupported address type: 0x%02x", atyp)
	}

	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, portBuf); err != nil {
		return "", 0, 0, fmt.Errorf("reading port: %w", err)
	}
	port = binary.BigEndian.Uint16(portBuf)

	return addr, port, atyp, nil
}

// SendReply sends a SOCKS5 reply with the given code and a zeroed bound address.
func SendReply(conn net.Conn, code byte) error {
	reply := []byte{0x05, code, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	_, err := conn.Write(reply)
	return err
}

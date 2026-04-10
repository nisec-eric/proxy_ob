package internal

import (
	"crypto/subtle"
	"encoding/binary"
	"fmt"
	"io"
	"net"
)

// Frame represents a single tunnel frame with SOCKS5-style address encoding.
type Frame struct {
	Atyp byte   // 0x01=IPv4, 0x03=Domain, 0x04=IPv6
	Addr []byte // address data (raw bytes for IPv4/IPv6, domain string bytes for domain)
	Port uint16 // destination port
	Data []byte // payload data
}

// WriteFrame serializes and encrypts a Frame, then writes it to conn.
// Wire format: [2-byte length BE] [encrypted(nonce+payload+tag)]
func WriteFrame(conn net.Conn, key [32]byte, frame *Frame) error {
	var buf []byte

	// atyp (1 byte)
	buf = append(buf, frame.Atyp)

	// address bytes based on Atyp
	switch frame.Atyp {
	case 0x01: // IPv4
		buf = append(buf, frame.Addr[:4]...)
	case 0x03: // Domain
		buf = append(buf, byte(len(frame.Addr)))
		buf = append(buf, frame.Addr...)
	case 0x04: // IPv6
		buf = append(buf, frame.Addr[:16]...)
	default:
		return fmt.Errorf("unsupported atyp: 0x%02x", frame.Atyp)
	}

	// port (2 bytes, big-endian)
	var portBuf [2]byte
	binary.BigEndian.PutUint16(portBuf[:], frame.Port)
	buf = append(buf, portBuf[:]...)

	// data payload
	buf = append(buf, frame.Data...)

	// encrypt
	encrypted, err := Encrypt(key, buf)
	if err != nil {
		return fmt.Errorf("encrypt frame: %w", err)
	}

	// write length prefix + encrypted data
	var lenBuf [2]byte
	binary.BigEndian.PutUint16(lenBuf[:], uint16(len(encrypted)))
	if _, err := conn.Write(lenBuf[:]); err != nil {
		return fmt.Errorf("write length: %w", err)
	}
	if _, err := conn.Write(encrypted); err != nil {
		return fmt.Errorf("write encrypted frame: %w", err)
	}

	return nil
}

// ReadFrame reads and decrypts a Frame from conn.
func ReadFrame(conn net.Conn, key [32]byte) (*Frame, error) {
	// read 2-byte length prefix
	var lenBuf [2]byte
	if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
		return nil, fmt.Errorf("read length: %w", err)
	}
	length := binary.BigEndian.Uint16(lenBuf[:])

	// read encrypted data
	encrypted := make([]byte, length)
	if _, err := io.ReadFull(conn, encrypted); err != nil {
		return nil, fmt.Errorf("read encrypted data: %w", err)
	}

	// decrypt
	plaintext, err := Decrypt(key, encrypted)
	if err != nil {
		return nil, fmt.Errorf("decrypt frame: %w", err)
	}

	// parse plaintext
	if len(plaintext) < 1 {
		return nil, fmt.Errorf("plaintext too short: missing atyp")
	}

	frame := &Frame{}
	offset := 0

	// atyp (1 byte)
	frame.Atyp = plaintext[offset]
	offset++

	// address based on Atyp
	switch frame.Atyp {
	case 0x01: // IPv4
		if offset+4 > len(plaintext) {
			return nil, fmt.Errorf("plaintext too short for IPv4 address")
		}
		frame.Addr = net.IP(plaintext[offset : offset+4])
		offset += 4

	case 0x03: // Domain
		if offset+1 > len(plaintext) {
			return nil, fmt.Errorf("plaintext too short for domain length")
		}
		domainLen := int(plaintext[offset])
		offset++
		if offset+domainLen > len(plaintext) {
			return nil, fmt.Errorf("plaintext too short for domain: need %d bytes", domainLen)
		}
		frame.Addr = make([]byte, domainLen)
		copy(frame.Addr, plaintext[offset:offset+domainLen])
		offset += domainLen

	case 0x04: // IPv6
		if offset+16 > len(plaintext) {
			return nil, fmt.Errorf("plaintext too short for IPv6 address")
		}
		frame.Addr = net.IP(plaintext[offset : offset+16])
		offset += 16

	default:
		return nil, fmt.Errorf("unsupported atyp: 0x%02x", frame.Atyp)
	}

	// port (2 bytes, big-endian)
	if offset+2 > len(plaintext) {
		return nil, fmt.Errorf("plaintext too short for port")
	}
	frame.Port = binary.BigEndian.Uint16(plaintext[offset : offset+2])
	offset += 2

	// remaining bytes = data
	if offset < len(plaintext) {
		frame.Data = make([]byte, len(plaintext)-offset)
		copy(frame.Data, plaintext[offset:])
	}

	return frame, nil
}

// ClientHandshake performs the client side of the tunnel handshake.
func ClientHandshake(conn net.Conn, key [32]byte) error {
	token := HandshakeToken(key)

	// send: [0x01 version] + token[0:32]
	hs := make([]byte, 0, 33)
	hs = append(hs, 0x01)
	hs = append(hs, token[:]...)
	if _, err := conn.Write(hs); err != nil {
		return fmt.Errorf("send handshake: %w", err)
	}

	// read server reply: 2 bytes [version, status]
	var reply [2]byte
	if _, err := io.ReadFull(conn, reply[:]); err != nil {
		return fmt.Errorf("read handshake reply: %w", err)
	}

	if reply[1] != 0x00 {
		return fmt.Errorf("handshake rejected: status 0x%02x", reply[1])
	}

	return nil
}

// ServerHandshake performs the server side of the tunnel handshake.
func ServerHandshake(conn net.Conn, key [32]byte) error {
	// read client handshake: 33 bytes (1 version + 32 token)
	var hs [33]byte
	if _, err := io.ReadFull(conn, hs[:]); err != nil {
		return fmt.Errorf("read handshake: %w", err)
	}

	// verify version
	if hs[0] != 0x01 {
		return fmt.Errorf("unsupported handshake version: 0x%02x", hs[0])
	}

	// compute expected token and compare
	expectedToken := HandshakeToken(key)
	if subtle.ConstantTimeCompare(hs[1:], expectedToken[:]) != 1 {
		// send failure reply
		conn.Write([]byte{0x01, 0x01})
		return fmt.Errorf("authentication failed")
	}

	// send success reply
	if _, err := conn.Write([]byte{0x01, 0x00}); err != nil {
		return fmt.Errorf("send handshake success: %w", err)
	}

	return nil
}

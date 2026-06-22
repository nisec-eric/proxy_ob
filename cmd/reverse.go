package cmd

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"

	"proxy_ob/internal"
)

func RunReverse() {
	cfg, err := parseConfig()
	if err != nil {
		if err == internal.ErrHelp {
			os.Exit(0)
		}
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	key := internal.DeriveKey(cfg.Key)

	listenPort, targetAddr, err := parseReverseSpec(cfg.Reverse)
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid reverse spec %q: %v\n", cfg.Reverse, err)
		os.Exit(1)
	}

	controlConn, err := net.DialTimeout("tcp", cfg.Server, dialTimeout)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dial server: %v\n", err)
		os.Exit(1)
	}

	if err := internal.ClientHandshake(controlConn, key); err != nil {
		fmt.Fprintf(os.Stderr, "handshake: %v\n", err)
		os.Exit(1)
	}

	regFrame := &internal.Frame{
		Atyp: 0x00,
		Port: listenPort,
		Data: []byte(targetAddr),
	}
	if err := internal.WriteFrame(controlConn, key, regFrame); err != nil {
		fmt.Fprintf(os.Stderr, "send registration: %v\n", err)
		os.Exit(1)
	}

	infof("reverse tunnel: server :%d -> local %s", listenPort, targetAddr)

	for {
		frame, err := internal.ReadFrame(controlConn, key)
		if err != nil {
			infof("control connection lost: %v", err)
			return
		}

		if frame.Atyp == 0x02 {
			sessionID := string(frame.Data)
			go handleReverseDataConn(cfg.Server, key, sessionID, targetAddr)
		}
	}
}

func parseReverseSpec(spec string) (listenPort uint16, targetAddr string, err error) {
	parts := strings.SplitN(spec, ":", 2)
	if len(parts) != 2 {
		return 0, "", fmt.Errorf("expected format listen_port:target_host:target_port")
	}

	port, parseErr := strconv.ParseUint(parts[0], 10, 16)
	if parseErr != nil {
		return 0, "", fmt.Errorf("invalid listen port: %w", parseErr)
	}

	return uint16(port), parts[1], nil
}

func handleReverseDataConn(serverAddr string, key [32]byte, sessionID, targetAddr string) {
	dataConn, err := net.DialTimeout("tcp", serverAddr, dialTimeout)
	if err != nil {
		verbosef("reverse data dial: %v", err)
		return
	}

	if err := internal.ClientHandshake(dataConn, key); err != nil {
		verbosef("reverse data handshake: %v", err)
		dataConn.Close()
		return
	}

	initFrame := &internal.Frame{
		Atyp: 0x05,
		Data: []byte(sessionID),
	}
	if err := internal.WriteFrame(dataConn, key, initFrame); err != nil {
		verbosef("reverse data init: %v", err)
		dataConn.Close()
		return
	}

	localConn, err := net.DialTimeout("tcp", targetAddr, dialTimeout)
	if err != nil {
		verbosef("reverse local dial %s: %v", targetAddr, err)
		dataConn.Close()
		return
	}

	verbosef("reverse data %s -> %s", sessionID, targetAddr)
	relay(localConn, dataConn, key)
}

func generateSessionID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return hex.EncodeToString(b)
}

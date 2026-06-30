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

	bindAddr, listenPort, targetAddr, isProxy, err := parseReverseSpec(cfg.Reverse)
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid reverse spec %q: %v\n", cfg.Reverse, err)
		os.Exit(1)
	}

	controlConn, err := dialServer(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dial server: %v\n", err)
		os.Exit(1)
	}

	if err := internal.ClientHandshake(controlConn, key); err != nil {
		fmt.Fprintf(os.Stderr, "handshake: %v\n", err)
		os.Exit(1)
	}

	regData := bindAddr + "\n" + targetAddr
	regFrame := &internal.Frame{
		Atyp: 0x00,
		Port: listenPort,
		Data: []byte(regData),
	}
	if err := internal.WriteFrame(controlConn, key, regFrame); err != nil {
		fmt.Fprintf(os.Stderr, "send registration: %v\n", err)
		os.Exit(1)
	}

	if isProxy {
		infof("reverse proxy: %s:%d -> client (dynamic target)", bindAddr, listenPort)
	} else {
		infof("reverse tunnel: %s:%d -> client:%s", bindAddr, listenPort, targetAddr)
	}

	for {
		frame, err := internal.ReadFrame(controlConn, key)
		if err != nil {
			infof("control connection lost: %v", err)
			return
		}

		sessionID := string(frame.Data)

		switch frame.Atyp {
		case 0x02:
			go handleReverseDataConn(cfg, key, sessionID, targetAddr)
		default:
			dynamicTarget := resolveFrameTarget(frame.Atyp, frame.Addr, frame.Port)
			if dynamicTarget == "" {
				verbosef("reverse proxy: invalid target from session %s", sessionID)
				continue
			}
			go handleReverseDataConn(cfg, key, sessionID, dynamicTarget)
		}
	}
}

func parseReverseSpec(spec string) (bindAddr string, listenPort uint16, targetAddr string, isProxy bool, err error) {
	bindAddr = "127.0.0.1"
	if strings.HasPrefix(spec, ":") {
		bindAddr = "0.0.0.0"
		spec = spec[1:]
	}

	parts := strings.SplitN(spec, ":", 2)
	port, parseErr := strconv.ParseUint(parts[0], 10, 16)
	if parseErr != nil {
		return "", 0, "", false, fmt.Errorf("invalid listen port: %w", parseErr)
	}

	if len(parts) == 1 {
		return bindAddr, uint16(port), "", true, nil
	}

	return bindAddr, uint16(port), parts[1], false, nil
}

func resolveFrameTarget(atyp byte, addr []byte, port uint16) string {
	switch atyp {
	case 0x01:
		return fmt.Sprintf("%s:%d", net.IP(addr).String(), port)
	case 0x03:
		return fmt.Sprintf("%s:%d", string(addr), port)
	case 0x04:
		return fmt.Sprintf("[%s]:%d", net.IP(addr).String(), port)
	}
	return ""
}

func handleReverseDataConn(cfg *internal.Config, key [32]byte, sessionID, targetAddr string) {
	dataConn, err := dialServer(cfg)
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

	localConn, err := dialTarget(cfg, targetAddr)
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

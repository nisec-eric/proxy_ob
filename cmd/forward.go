package cmd

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strconv"

	"proxy_ob/internal"
)

func RunForward() {
	cfg, err := internal.Parse(os.Args[1:])
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	key := internal.DeriveKey(cfg.Key)

	atyp, addrBytes, port, err := parseTargetAddr(cfg.Target)
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid target %q: %v\n", cfg.Target, err)
		os.Exit(1)
	}

	listener, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		fmt.Fprintf(os.Stderr, "listen error: %v\n", err)
		os.Exit(1)
	}

	log.Printf("forwarding %s -> %s via %s", cfg.Listen, cfg.Target, cfg.Server)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt)
	go func() {
		<-sigCh
		listener.Close()
		cancel()
	}()

	for {
		conn, err := listener.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
				log.Printf("accept error: %v", err)
				continue
			}
		}
		log.Printf("connection from %s", conn.RemoteAddr())
		go handleForwardConnection(conn, cfg, key, atyp, addrBytes, port)
	}
}

func parseTargetAddr(target string) (atyp byte, addr []byte, port uint16, err error) {
	host, portStr, splitErr := net.SplitHostPort(target)
	if splitErr != nil {
		return 0, nil, 0, fmt.Errorf("split host:port: %w", splitErr)
	}

	portInt, parseErr := strconv.ParseUint(portStr, 10, 16)
	if parseErr != nil {
		return 0, nil, 0, fmt.Errorf("invalid port: %w", parseErr)
	}

	if ip := net.ParseIP(host); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			atyp = 0x01
			addr = ip4
		} else {
			atyp = 0x04
			addr = ip.To16()
		}
	} else {
		atyp = 0x03
		addr = []byte(host)
	}

	return atyp, addr, uint16(portInt), nil
}

func handleForwardConnection(localConn net.Conn, cfg *internal.Config, key [32]byte, atyp byte, addr []byte, port uint16) {
	defer localConn.Close()

	tunnelConn, err := net.Dial("tcp", cfg.Server)
	if err != nil {
		log.Printf("dial tunnel %s: %v", cfg.Server, err)
		return
	}

	if err := internal.ClientHandshake(tunnelConn, key); err != nil {
		log.Printf("handshake failed: %v", err)
		tunnelConn.Close()
		return
	}

	addrFrame := &internal.Frame{
		Atyp: atyp,
		Addr: addr,
		Port: port,
		Data: nil,
	}
	if err := internal.WriteFrame(tunnelConn, key, addrFrame); err != nil {
		log.Printf("send target frame: %v", err)
		tunnelConn.Close()
		return
	}

	relay(localConn, tunnelConn, key)
}

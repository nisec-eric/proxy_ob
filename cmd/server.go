package cmd

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"sync"

	"proxy_ob/internal"
)

// RunServer starts the encrypted tunnel server.
func RunServer() {
	cfg, err := internal.Parse(os.Args[1:])
	if err != nil {
		log.Fatalf("parse config: %v", err)
	}

	key := internal.DeriveKey(cfg.Key)

	listener, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		log.Fatalf("listen: %v", err)
	}
	fmt.Fprintf(os.Stderr, "listening on %s\n", cfg.Listen)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Graceful shutdown on interrupt.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt)
	go func() {
		<-sigCh
		fmt.Fprintf(os.Stderr, "shutting down\n")
		cancel()
		listener.Close()
	}()

	for {
		conn, err := listener.Accept()
		if err != nil {
			// Listener closed (shutdown).
			select {
			case <-ctx.Done():
				return
			default:
				log.Printf("accept: %v", err)
				continue
			}
		}
		fmt.Fprintf(os.Stderr, "connection from %s\n", conn.RemoteAddr())
		go handleServerConnection(conn, key)
	}
}

func handleServerConnection(tunnelConn net.Conn, key [32]byte) {
	defer tunnelConn.Close()

	// Server-side tunnel handshake.
	if err := internal.ServerHandshake(tunnelConn, key); err != nil {
		log.Printf("handshake failed from %s: %v", tunnelConn.RemoteAddr(), err)
		return
	}

	// Read target address frame.
	frame, err := internal.ReadFrame(tunnelConn, key)
	if err != nil {
		log.Printf("read target frame: %v", err)
		return
	}

	// Construct target address string.
	var targetAddrPort string
	switch frame.Atyp {
	case 0x01: // IPv4
		targetAddrPort = fmt.Sprintf("%s:%d", net.IP(frame.Addr).String(), frame.Port)
	case 0x03: // Domain
		targetAddrPort = fmt.Sprintf("%s:%d", string(frame.Addr), frame.Port)
	case 0x04: // IPv6
		targetAddrPort = fmt.Sprintf("[%s]:%d", net.IP(frame.Addr).String(), frame.Port)
	default:
		log.Printf("unsupported atyp: 0x%02x", frame.Atyp)
		return
	}

	// Dial target.
	targetConn, err := net.Dial("tcp", targetAddrPort)
	if err != nil {
		log.Printf("dial target %s: %v", targetAddrPort, err)
		return
	}
	defer targetConn.Close()

	fmt.Fprintf(os.Stderr, "connected to target %s\n", targetAddrPort)

	// Write initial payload if present.
	if len(frame.Data) > 0 {
		if _, err := targetConn.Write(frame.Data); err != nil {
			log.Printf("write initial payload: %v", err)
			return
		}
	}

	// Bidirectional relay.
	var wg sync.WaitGroup
	wg.Add(2)

	done := make(chan struct{})
	var closeOnce sync.Once
	closeAll := func() {
		closeOnce.Do(func() {
			tunnelConn.Close()
			targetConn.Close()
		})
	}

	// goroutine 1: tunnel → target.
	go func() {
		defer wg.Done()
		for {
			f, err := internal.ReadFrame(tunnelConn, key)
			if err != nil {
				break
			}
			if len(f.Data) > 0 {
				if _, err := targetConn.Write(f.Data); err != nil {
					break
				}
			}
		}
		closeAll()
	}()

	// goroutine 2: target → tunnel.
	go func() {
		defer wg.Done()
		buf := make([]byte, 32*1024)
		for {
			n, err := targetConn.Read(buf)
			if n > 0 {
				writeErr := internal.WriteFrame(tunnelConn, key, &internal.Frame{
					Atyp: 0x01,
					Addr: make([]byte, 4),
					Data: buf[:n],
				})
				if writeErr != nil {
					break
				}
			}
			if err != nil {
				break
			}
		}
		closeAll()
	}()

	// Wait for both goroutines, ensuring clean shutdown.
	go func() {
		wg.Wait()
		close(done)
	}()

	<-done
}

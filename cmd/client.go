package cmd

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"sync"

	"proxy_ob/internal"
)

// RunClient starts the local SOCKS5 listener and relays connections through
// an encrypted tunnel to the remote server.
func RunClient() {
	cfg, err := internal.Parse(os.Args[1:])
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	key := internal.DeriveKey(cfg.Key)

	listener, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		fmt.Fprintf(os.Stderr, "listen error: %v\n", err)
		os.Exit(1)
	}

	log.Printf("listening on %s", cfg.Listen)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Graceful shutdown on SIGINT.
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
		go handleConnection(conn, cfg, key)
	}
}

// handleConnection performs the SOCKS5 handshake, establishes a tunnel to the
// remote server, and relays data bidirectionally.
func handleConnection(socksConn net.Conn, cfg *internal.Config, key [32]byte) {
	defer socksConn.Close()

	// SOCKS5 handshake.
	if err := internal.Handshake(socksConn); err != nil {
		return
	}

	// Read target address from the SOCKS5 client.
	addr, port, atyp, err := internal.ReadRequest(socksConn)
	if err != nil {
		return
	}

	// Connect to the remote tunnel server.
	tunnelConn, err := net.Dial("tcp", cfg.Server)
	if err != nil {
		internal.SendReply(socksConn, internal.ReplyHostUnreachable)
		return
	}

	// Tunnel handshake.
	if err := internal.ClientHandshake(tunnelConn, key); err != nil {
		internal.SendReply(socksConn, internal.ReplyGeneralFailure)
		tunnelConn.Close()
		return
	}

	// Convert address string back to bytes based on atyp.
	var addrBytes []byte
	switch atyp {
	case 0x01: // IPv4
		addrBytes = net.ParseIP(addr).To4()
	case 0x03: // Domain
		addrBytes = []byte(addr)
	case 0x04: // IPv6
		addrBytes = net.ParseIP(addr).To16()
	default:
		internal.SendReply(socksConn, internal.ReplyGeneralFailure)
		tunnelConn.Close()
		return
	}

	// Send target address frame to the tunnel server.
	addrFrame := &internal.Frame{
		Atyp: atyp,
		Addr: addrBytes,
		Port: port,
		Data: nil,
	}
	if err := internal.WriteFrame(tunnelConn, key, addrFrame); err != nil {
		internal.SendReply(socksConn, internal.ReplyGeneralFailure)
		tunnelConn.Close()
		return
	}

	// Tell the SOCKS5 client that the connection is established.
	if err := internal.SendReply(socksConn, internal.ReplySucceeded); err != nil {
		tunnelConn.Close()
		return
	}

	// Bidirectional relay.
	relay(socksConn, tunnelConn, key)
}

// relay copies data between the SOCKS5 connection and the encrypted tunnel.
// Reads from socksConn are wrapped in frames and encrypted before writing to
// tunnelConn. Reads from tunnelConn are decrypted via ReadFrame and the payload
// is written directly to socksConn.
func relay(socksConn, tunnelConn net.Conn, key [32]byte) {
	var closeOnce sync.Once
	closeAll := func() {
		closeOnce.Do(func() {
			socksConn.Close()
			tunnelConn.Close()
		})
	}
	defer closeAll()

	done := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(2)

	// socks5 → tunnel: read raw bytes, wrap in encrypted frame.
	go func() {
		defer wg.Done()
		buf := make([]byte, 32*1024)
		for {
			n, err := socksConn.Read(buf)
			if n > 0 {
				frame := &internal.Frame{
					Atyp: 0x01,
					Addr: make([]byte, 4),
					Port: 0,
					Data: buf[:n],
				}
				if writeErr := internal.WriteFrame(tunnelConn, key, frame); writeErr != nil {
					closeAll()
					return
				}
			}
			if err != nil {
				closeAll()
				return
			}
		}
	}()

	// tunnel → socks5: decrypt frame, write payload.
	go func() {
		defer wg.Done()
		for {
			frame, err := internal.ReadFrame(tunnelConn, key)
			if err != nil {
				if err != io.EOF && err != io.ErrUnexpectedEOF {
					// ReadFrame wraps errors, so EOF may appear as a different message.
				}
				closeAll()
				return
			}
			if len(frame.Data) > 0 {
				if _, writeErr := socksConn.Write(frame.Data); writeErr != nil {
					closeAll()
					return
				}
			}
		}
	}()

	// Wait for one goroutine to finish, then signal the other.
	go func() {
		wg.Wait()
		close(done)
	}()

	<-done
}

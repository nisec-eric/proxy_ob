package cmd

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"sync"

	"proxy_ob/internal"
)

func RunClient() {
	cfg, err := parseConfig()
	if err != nil {
		if err == internal.ErrHelp {
			os.Exit(0)
		}
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	key := internal.DeriveKey(cfg.Key)

	listener, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		fmt.Fprintf(os.Stderr, "listen error: %v\n", err)
		os.Exit(1)
	}

	infof("listening on %s (SOCKS5)", cfg.Listen)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt)
	go func() {
		<-sigCh
		infof("shutting down")
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
				infof("accept error: %v", err)
				continue
			}
		}
		go handleConnection(conn, cfg, key)
	}
}

func handleConnection(socksConn net.Conn, cfg *internal.Config, key [32]byte) {
	defer socksConn.Close()

	if err := internal.Handshake(socksConn); err != nil {
		return
	}

	addr, port, atyp, err := internal.ReadRequest(socksConn)
	if err != nil {
		return
	}

	verbosef("socks5 %s -> %s:%d", socksConn.RemoteAddr(), addr, port)

	tunnelConn, err := net.Dial("tcp", cfg.Server)
	if err != nil {
		internal.SendReply(socksConn, internal.ReplyHostUnreachable)
		return
	}

	if err := internal.ClientHandshake(tunnelConn, key); err != nil {
		internal.SendReply(socksConn, internal.ReplyGeneralFailure)
		tunnelConn.Close()
		return
	}

	var addrBytes []byte
	switch atyp {
	case 0x01:
		addrBytes = net.ParseIP(addr).To4()
	case 0x03:
		addrBytes = []byte(addr)
	case 0x04:
		addrBytes = net.ParseIP(addr).To16()
	default:
		internal.SendReply(socksConn, internal.ReplyGeneralFailure)
		tunnelConn.Close()
		return
	}

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

	if err := internal.SendReply(socksConn, internal.ReplySucceeded); err != nil {
		tunnelConn.Close()
		return
	}

	relay(socksConn, tunnelConn, key)
}

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

	go func() {
		defer wg.Done()
		for {
			frame, err := internal.ReadFrame(tunnelConn, key)
			if err != nil {
				if err != io.EOF && err != io.ErrUnexpectedEOF {
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

	go func() {
		wg.Wait()
		close(done)
	}()

	<-done
}

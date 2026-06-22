package cmd

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/signal"
	"sync"

	"proxy_ob/internal"
)

func RunServer() {
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

	infof("listening on %s (tunnel)", cfg.Listen)

	const maxConns = 1024
	sem := make(chan struct{}, maxConns)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt)
	go func() {
		<-sigCh
		infof("shutting down")
		cancel()
		listener.Close()
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
		sem <- struct{}{}
		go func() {
			defer func() { <-sem }()
			handleServerConnection(conn, key)
		}()
	}
}

func handleServerConnection(tunnelConn net.Conn, key [32]byte) {
	defer tunnelConn.Close()

	if err := internal.ServerHandshake(tunnelConn, key); err != nil {
		verbosef("handshake failed from %s: %v", tunnelConn.RemoteAddr(), err)
		return
	}

	frame, err := internal.ReadFrame(tunnelConn, key)
	if err != nil {
		verbosef("read target frame: %v", err)
		return
	}

	switch frame.Atyp {
	case 0x00:
		handleReverseRegistration(tunnelConn, key, frame)
		return
	case 0x05:
		handleReverseData(tunnelConn, key, frame)
		return
	default:
		handleProxyTarget(tunnelConn, key, frame)
	}
}

func handleProxyTarget(tunnelConn net.Conn, key [32]byte, frame *internal.Frame) {
	defer tunnelConn.Close()

	var targetAddrPort string
	switch frame.Atyp {
	case 0x01:
		targetAddrPort = fmt.Sprintf("%s:%d", net.IP(frame.Addr).String(), frame.Port)
	case 0x03:
		targetAddrPort = fmt.Sprintf("%s:%d", string(frame.Addr), frame.Port)
	case 0x04:
		targetAddrPort = fmt.Sprintf("[%s]:%d", net.IP(frame.Addr).String(), frame.Port)
	default:
		verbosef("unsupported atyp: 0x%02x", frame.Atyp)
		return
	}

	verbosef("tunnel %s -> target %s", tunnelConn.RemoteAddr(), targetAddrPort)

	targetConn, err := net.DialTimeout("tcp", targetAddrPort, dialTimeout)
	if err != nil {
		verbosef("dial target %s: %v", targetAddrPort, err)
		return
	}
	defer targetConn.Close()

	if len(frame.Data) > 0 {
		if _, err := targetConn.Write(frame.Data); err != nil {
			verbosef("write initial payload: %v", err)
			return
		}
	}

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

	go func() {
		wg.Wait()
		close(done)
	}()

	<-done
}

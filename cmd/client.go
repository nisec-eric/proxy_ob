package cmd

import (
	"bufio"
	"context"
	"fmt"
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

	infof("listening on %s (SOCKS5 + HTTP proxy)", cfg.Listen)

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

type bufferedConn struct {
	r  *bufio.Reader
	net.Conn
}

func (bc *bufferedConn) Read(b []byte) (int, error) {
	return bc.r.Read(b)
}

func handleConnection(conn net.Conn, cfg *internal.Config, key [32]byte) {
	defer conn.Close()

	br := bufio.NewReader(conn)
	peek, err := br.Peek(1)
	if err != nil {
		return
	}

	if peek[0] == 0x05 {
		handleSOCKS5(&bufferedConn{r: br, Conn: conn}, cfg, key)
	} else {
		handleHTTPProxy(br, conn, cfg, key)
	}
}

func handleSOCKS5(conn net.Conn, cfg *internal.Config, key [32]byte) {
	if err := internal.Handshake(conn); err != nil {
		verbosef("socks5 handshake: %v", err)
		return
	}

	addr, port, atyp, err := internal.ReadRequest(conn)
	if err != nil {
		verbosef("socks5 read request: %v", err)
		return
	}

	verbosef("socks5 %s -> %s:%d", conn.RemoteAddr(), addr, port)

	tunnelConn, err := net.DialTimeout("tcp", cfg.Server, dialTimeout)
	if err != nil {
		verbosef("dial tunnel %s: %v", cfg.Server, err)
		internal.SendReply(conn, internal.ReplyHostUnreachable)
		return
	}

	if err := internal.ClientHandshake(tunnelConn, key); err != nil {
		internal.SendReply(conn, internal.ReplyGeneralFailure)
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
		internal.SendReply(conn, internal.ReplyGeneralFailure)
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
		internal.SendReply(conn, internal.ReplyGeneralFailure)
		tunnelConn.Close()
		return
	}

	if err := internal.SendReply(conn, internal.ReplySucceeded); err != nil {
		tunnelConn.Close()
		return
	}

	relay(conn, tunnelConn, key)
}

func handleHTTPProxy(br *bufio.Reader, conn net.Conn, cfg *internal.Config, key [32]byte) {
	host, port, isConnect, initialData, err := internal.ReadHTTPProxyRequest(br)
	if err != nil {
		verbosef("http proxy parse: %v", err)
		return
	}

	verbosef("http %s -> %s:%d (connect=%v)", conn.RemoteAddr(), host, port, isConnect)

	atyp, addrBytes := hostToAddrBytes(host)

	tunnelConn, err := net.DialTimeout("tcp", cfg.Server, dialTimeout)
	if err != nil {
		verbosef("dial tunnel %s: %v", cfg.Server, err)
		if isConnect {
			internal.SendHTTPResponse(conn, 502, "Bad Gateway")
		}
		return
	}

	if err := internal.ClientHandshake(tunnelConn, key); err != nil {
		tunnelConn.Close()
		if isConnect {
			internal.SendHTTPResponse(conn, 502, "Bad Gateway")
		}
		return
	}

	addrFrame := &internal.Frame{
		Atyp: atyp,
		Addr: addrBytes,
		Port: port,
		Data: initialData,
	}
	if err := internal.WriteFrame(tunnelConn, key, addrFrame); err != nil {
		tunnelConn.Close()
		if isConnect {
			internal.SendHTTPResponse(conn, 502, "Bad Gateway")
		}
		return
	}

	if isConnect {
		if err := internal.SendHTTPResponse(conn, 200, "Connection established"); err != nil {
			tunnelConn.Close()
			return
		}
	}

	relay(&bufferedConn{r: br, Conn: conn}, tunnelConn, key)
}

func hostToAddrBytes(host string) (byte, []byte) {
	if ip := net.ParseIP(host); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			return 0x01, ip4
		}
		return 0x04, ip.To16()
	}
	return 0x03, []byte(host)
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

package cmd

import (
	"bufio"
	"fmt"
	"net"
	"strings"
	"sync"

	"proxy_ob/internal"
)

type pendingConn struct {
	conn        net.Conn
	initialData []byte
}

var pendingReverseConns sync.Map

func handleReverseRegistration(controlConn net.Conn, key [32]byte, frame *internal.Frame) {
	listenPort := frame.Port

	dataParts := strings.SplitN(string(frame.Data), "\n", 2)
	bindAddr := dataParts[0]
	targetAddr := ""
	if len(dataParts) > 1 {
		targetAddr = dataParts[1]
	}
	isProxy := targetAddr == ""

	listener, err := net.Listen("tcp", fmt.Sprintf("%s:%d", bindAddr, listenPort))
	if err != nil {
		verbosef("reverse listen %s:%d: %v", bindAddr, listenPort, err)
		return
	}
	defer listener.Close()

	var controlMu sync.Mutex

	if isProxy {
		infof("reverse proxy: %s:%d (SOCKS5/HTTP) -> client", bindAddr, listenPort)
		go acceptReverseProxy(listener, controlConn, key, &controlMu)
	} else {
		infof("reverse tunnel: %s:%d -> client:%s", bindAddr, listenPort, targetAddr)
		go acceptReverseFixed(listener, controlConn, key, &controlMu)
	}

	buf := make([]byte, 1)
	for {
		_, err := controlConn.Read(buf)
		if err != nil {
			break
		}
	}

	infof("reverse %s:%d closed", bindAddr, listenPort)
}

func acceptReverseFixed(listener net.Listener, controlConn net.Conn, key [32]byte, mu *sync.Mutex) {
	for {
		userConn, err := listener.Accept()
		if err != nil {
			return
		}

		sessionID := generateSessionID()
		pendingReverseConns.Store(sessionID, &pendingConn{conn: userConn})

		verbosef("reverse fixed: new connection session=%s", sessionID)

		mu.Lock()
		err = internal.WriteFrame(controlConn, key, &internal.Frame{
			Atyp: 0x02,
			Data: []byte(sessionID),
		})
		mu.Unlock()

		if err != nil {
			pendingReverseConns.Delete(sessionID)
			userConn.Close()
			return
		}
	}
}

func acceptReverseProxy(listener net.Listener, controlConn net.Conn, key [32]byte, mu *sync.Mutex) {
	for {
		userConn, err := listener.Accept()
		if err != nil {
			return
		}
		go handleReverseProxyUserConn(userConn, controlConn, key, mu)
	}
}

func handleReverseProxyUserConn(userConn net.Conn, controlConn net.Conn, key [32]byte, mu *sync.Mutex) {
	br := bufio.NewReader(userConn)
	peek, err := br.Peek(1)
	if err != nil {
		userConn.Close()
		return
	}

	var atyp byte
	var addrBytes []byte
	var port uint16
	var initialData []byte
	var connForRelay net.Conn = userConn

	if peek[0] == 0x05 {
		bc := &bufferedConn{r: br, Conn: userConn}
		if err := internal.Handshake(bc); err != nil {
			verbosef("reverse proxy socks5 handshake: %v", err)
			userConn.Close()
			return
		}
		addr, p, _, err := internal.ReadRequest(bc)
		if err != nil {
			verbosef("reverse proxy socks5 read request: %v", err)
			userConn.Close()
			return
		}
		atyp, addrBytes = hostToAddrBytes(addr)
		port = p
		internal.SendReply(bc, internal.ReplySucceeded)
		connForRelay = bc
	} else {
		host, p, isConnect, data, err := internal.ReadHTTPProxyRequest(br)
		if err != nil {
			verbosef("reverse proxy http parse: %v", err)
			userConn.Close()
			return
		}
		atyp, addrBytes = hostToAddrBytes(host)
		port = p
		initialData = data
		if isConnect {
			internal.SendHTTPResponse(userConn, 200, "Connection established")
		}
		connForRelay = &bufferedConn{r: br, Conn: userConn}
	}

	sessionID := generateSessionID()
	pendingReverseConns.Store(sessionID, &pendingConn{
		conn:        connForRelay,
		initialData: initialData,
	})

	verbosef("reverse proxy: session=%s target=%s:%d", sessionID, hostFromAddr(atyp, addrBytes), port)

	mu.Lock()
	err = internal.WriteFrame(controlConn, key, &internal.Frame{
		Atyp: atyp,
		Addr: addrBytes,
		Port: port,
		Data: []byte(sessionID),
	})
	mu.Unlock()

	if err != nil {
		pendingReverseConns.Delete(sessionID)
		userConn.Close()
		return
	}
}

func handleReverseData(tunnelConn net.Conn, key [32]byte, frame *internal.Frame) {
	sessionID := string(frame.Data)

	val, ok := pendingReverseConns.LoadAndDelete(sessionID)
	if !ok {
		verbosef("reverse data: unknown session %s", sessionID)
		return
	}
	pc := val.(*pendingConn)

	if len(pc.initialData) > 0 {
		if err := internal.WriteFrame(tunnelConn, key, &internal.Frame{
			Atyp: 0x01,
			Addr: make([]byte, 4),
			Data: pc.initialData,
		}); err != nil {
			verbosef("reverse data: write initial payload: %v", err)
			pc.conn.Close()
			return
		}
	}

	verbosef("reverse data: session %s paired", sessionID)
	relay(pc.conn, tunnelConn, key)
}

func hostFromAddr(atyp byte, addr []byte) string {
	switch atyp {
	case 0x01, 0x04:
		return net.IP(addr).String()
	case 0x03:
		return string(addr)
	}
	return "?"
}

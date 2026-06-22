package cmd

import (
	"fmt"
	"net"
	"sync"

	"proxy_ob/internal"
)

var pendingReverseConns sync.Map

func handleReverseRegistration(controlConn net.Conn, key [32]byte, frame *internal.Frame) {
	listenPort := frame.Port
	targetAddr := string(frame.Data)

	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", listenPort))
	if err != nil {
		verbosef("reverse listen :%d: %v", listenPort, err)
		return
	}
	defer listener.Close()

	infof("reverse tunnel: :%d -> client:%s", listenPort, targetAddr)

	go func() {
		for {
			userConn, err := listener.Accept()
			if err != nil {
				return
			}

			sessionID := generateSessionID()
			pendingReverseConns.Store(sessionID, userConn)

			verbosef("reverse :%d new connection session=%s", listenPort, sessionID)

			if err := internal.WriteFrame(controlConn, key, &internal.Frame{
				Atyp: 0x02,
				Data: []byte(sessionID),
			}); err != nil {
				pendingReverseConns.Delete(sessionID)
				userConn.Close()
				return
			}
		}
	}()

	buf := make([]byte, 1)
	for {
		_, err := controlConn.Read(buf)
		if err != nil {
			break
		}
	}

	infof("reverse tunnel :%d closed", listenPort)
}

func handleReverseData(tunnelConn net.Conn, key [32]byte, frame *internal.Frame) {
	sessionID := string(frame.Data)

	val, ok := pendingReverseConns.LoadAndDelete(sessionID)
	if !ok {
		verbosef("reverse data: unknown session %s", sessionID)
		return
	}
	userConn := val.(net.Conn)

	verbosef("reverse data: session %s paired", sessionID)
	relay(userConn, tunnelConn, key)
}

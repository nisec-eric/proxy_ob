package cmd

import (
	"fmt"
	"net"

	"proxy_ob/internal"
)

func dialServer(cfg *internal.Config) (net.Conn, error) {
	if cfg.Proxy == "" {
		return net.DialTimeout("tcp", cfg.Server, dialTimeout)
	}
	conn, err := internal.DialThroughProxy(cfg.Proxy, cfg.ProxyAuth, cfg.Server, dialTimeout)
	if err != nil {
		return nil, fmt.Errorf("dial %s via %s: %w", cfg.Server, cfg.Proxy, err)
	}
	return conn, nil
}

func dialTarget(cfg *internal.Config, targetAddr string) (net.Conn, error) {
	if cfg.ExitProxy == "" {
		return net.DialTimeout("tcp", targetAddr, dialTimeout)
	}
	conn, err := internal.DialThroughProxy(cfg.ExitProxy, cfg.ProxyAuth, targetAddr, dialTimeout)
	if err != nil {
		return nil, fmt.Errorf("dial %s via %s: %w", targetAddr, cfg.ExitProxy, err)
	}
	return conn, nil
}

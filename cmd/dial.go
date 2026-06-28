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
	conn, err := internal.DialThroughProxy(cfg.Proxy, cfg.Server, dialTimeout)
	if err != nil {
		return nil, fmt.Errorf("dial %s via %s: %w", cfg.Server, cfg.Proxy, err)
	}
	return conn, nil
}

package internal

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
)

var ErrHelp = errors.New("help requested")

// Config holds the application configuration.
type Config struct {
	Mode       string `json:"mode"`        // "client", "server", "forward", or "reverse"
	Listen     string `json:"listen"`      // listen address
	Server     string `json:"server"`      // remote server address (client/forward/reverse only)
	Key        string `json:"key"`         // encryption key (hex or passphrase)
	Target     string `json:"target"`      // forward target address host:port (forward only)
	Reverse    string `json:"reverse"`     // reverse spec listen_port:target_host:target_port (reverse only)
	Proxy      string `json:"proxy"`       // upstream proxy URL (http://host:port or socks5://host:port)
	Verbose    bool   `json:"verbose"`     // enable verbose debug logging
	Daemon     bool   `json:"daemon"`      // run as background daemon
	ConfigFile string `json:"config_file"` // optional JSON config file path
}

// jsonConfig mirrors Config for JSON unmarshalling.
type jsonConfig struct {
	Mode    string `json:"mode"`
	Listen  string `json:"listen"`
	Server  string `json:"server"`
	Key     string `json:"key"`
	Target  string `json:"target"`
	Reverse string `json:"reverse"`
	Proxy   string `json:"proxy"`
	Verbose bool   `json:"verbose"`
	Daemon  bool   `json:"daemon"`
}

// Parse parses CLI flags and optional JSON config file.
// args is os.Args[1:] where the first element is the subcommand.
func Parse(args []string) (*Config, error) {
	if len(args) == 0 {
		return nil, fmt.Errorf("usage: proxy_ob <client|server|forward> [flags]")
	}

	mode := args[0]
	if mode != "client" && mode != "server" && mode != "forward" && mode != "reverse" {
		return nil, fmt.Errorf("unknown mode %q: must be \"client\", \"server\", \"forward\", or \"reverse\"", mode)
	}

	cfg := &Config{Mode: mode}

	// Set defaults per mode.
	switch mode {
	case "client":
		cfg.Listen = "127.0.0.1:1080"
	case "server":
		cfg.Listen = ":8388"
	}

	fs := flag.NewFlagSet(mode, flag.ContinueOnError)
	listen := fs.String("l", "", "listen address")
	server := fs.String("s", "", "remote server address (client/forward only)")
	key := fs.String("k", "", "encryption key (hex or passphrase)")
	configFile := fs.String("c", "", "optional JSON config file path")
	target := fs.String("t", "", "target address host:port (forward only)")
	reverse := fs.String("r", "", "reverse spec [bind:]port[:target] (reverse only)")
	proxy := fs.String("P", "", "upstream proxy URL (http://host:port or socks5://host:port)")
	verbose := fs.Bool("v", false, "verbose debug logging")
	daemon := fs.Bool("d", false, "run as background daemon")

	if err := fs.Parse(args[1:]); err != nil {
		if err == flag.ErrHelp {
			return nil, ErrHelp
		}
		return nil, fmt.Errorf("parsing flags: %w", err)
	}

	// Load JSON config if provided.
	if *configFile != "" {
		data, err := os.ReadFile(*configFile)
		if err != nil {
			return nil, fmt.Errorf("reading config file: %w", err)
		}
		var jc jsonConfig
		if err := json.Unmarshal(data, &jc); err != nil {
			return nil, fmt.Errorf("parsing config file: %w", err)
		}
		// JSON values as base; CLI flags override below.
		if jc.Listen != "" {
			cfg.Listen = jc.Listen
		}
		if jc.Server != "" {
			cfg.Server = jc.Server
		}
		if jc.Key != "" {
			cfg.Key = jc.Key
		}
		if jc.Target != "" {
			cfg.Target = jc.Target
		}
		if jc.Reverse != "" {
			cfg.Reverse = jc.Reverse
		}
		if jc.Proxy != "" {
			cfg.Proxy = jc.Proxy
		}
		cfg.Verbose = jc.Verbose
		cfg.Daemon = jc.Daemon
	}

	// CLI flags override JSON config and defaults.
	if *listen != "" {
		cfg.Listen = *listen
	}
	cfg.ConfigFile = *configFile

	if *server != "" {
		cfg.Server = *server
	}
	if *key != "" {
		cfg.Key = *key
	}
	if *target != "" {
		cfg.Target = *target
	}
	if *reverse != "" {
		cfg.Reverse = *reverse
	}
	if *proxy != "" {
		cfg.Proxy = *proxy
	}
	if *verbose {
		cfg.Verbose = true
	}
	if *daemon {
		cfg.Daemon = true
	}

	// Validate required fields.
	if cfg.Key == "" {
		return nil, fmt.Errorf("key is required: use -k flag or config file")
	}
	if mode == "client" && cfg.Server == "" {
		return nil, fmt.Errorf("server address is required in client mode: use -s flag or config file")
	}
	if mode == "forward" {
		if cfg.Server == "" {
			return nil, fmt.Errorf("server address is required in forward mode: use -s flag or config file")
		}
		if cfg.Target == "" {
			return nil, fmt.Errorf("target address is required in forward mode: use -t flag or config file")
		}
	}
	if mode == "reverse" {
		if cfg.Server == "" {
			return nil, fmt.Errorf("server address is required in reverse mode: use -s flag or config file")
		}
		if cfg.Reverse == "" {
			return nil, fmt.Errorf("reverse spec is required in reverse mode: use -r flag or config file")
		}
	}

	return cfg, nil
}

// DeriveKey derives a 32-byte key from a hex string or passphrase.
// If the input is exactly 64 hex characters, it is decoded directly.
// Otherwise, SHA-256 is applied to the passphrase.
func DeriveKey(key string) [32]byte {
	// Try hex decoding if exactly 64 hex characters.
	if len(key) == 64 {
		if b, err := hex.DecodeString(key); err == nil && len(b) == 32 {
			var out [32]byte
			copy(out[:], b)
			return out
		}
	}
	// Fallback: SHA-256 hash of passphrase.
	return sha256.Sum256([]byte(key))
}

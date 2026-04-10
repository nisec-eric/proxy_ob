package internal

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
)

// Config holds the application configuration.
type Config struct {
	Mode       string `json:"mode"`        // "client" or "server"
	Listen     string `json:"listen"`      // listen address
	Server     string `json:"server"`      // remote server address (client only)
	Key        string `json:"key"`         // encryption key (hex or passphrase)
	ConfigFile string `json:"config_file"` // optional JSON config file path
}

// jsonConfig mirrors Config for JSON unmarshalling.
type jsonConfig struct {
	Mode   string `json:"mode"`
	Listen string `json:"listen"`
	Server string `json:"server"`
	Key    string `json:"key"`
}

// Parse parses CLI flags and optional JSON config file.
// args is os.Args[1:] where the first element is the subcommand ("client" or "server").
func Parse(args []string) (*Config, error) {
	if len(args) == 0 {
		return nil, fmt.Errorf("usage: proxy_ob <client|server> [flags]")
	}

	mode := args[0]
	if mode != "client" && mode != "server" {
		return nil, fmt.Errorf("unknown mode %q: must be \"client\" or \"server\"", mode)
	}

	cfg := &Config{Mode: mode}

	// Set defaults per mode.
	switch mode {
	case "client":
		cfg.Listen = ":1080"
	case "server":
		cfg.Listen = ":8388"
	}

	fs := flag.NewFlagSet(mode, flag.ContinueOnError)
	listen := fs.String("l", "", "listen address")
	server := fs.String("s", "", "remote server address (client only)")
	key := fs.String("k", "", "encryption key (hex or passphrase)")
	configFile := fs.String("c", "", "optional JSON config file path")

	if err := fs.Parse(args[1:]); err != nil {
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
		cfg.ConfigFile = *configFile
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

	// Validate required fields.
	if cfg.Key == "" {
		return nil, fmt.Errorf("key is required: use -k flag or config file")
	}
	if mode == "client" && cfg.Server == "" {
		return nil, fmt.Errorf("server address is required in client mode: use -s flag or config file")
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

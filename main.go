package main

import (
	"fmt"
	"os"

	"proxy_ob/cmd"
)

const version = "v0.1.0"

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "Usage: proxy_ob <client|server|version> [flags]\n\n")
		fmt.Fprintf(os.Stderr, "Commands:\n")
		fmt.Fprintf(os.Stderr, "  client   Run as SOCKS5 client (local proxy)\n")
		fmt.Fprintf(os.Stderr, "  server   Run as tunnel server (remote proxy)\n")
		fmt.Fprintf(os.Stderr, "  version  Print version\n")
		os.Exit(1)
	}

	switch os.Args[1] {
	case "client":
		cmd.RunClient()
	case "server":
		cmd.RunServer()
	case "version":
		fmt.Println("proxy_ob", version)
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n", os.Args[1])
		fmt.Fprintf(os.Stderr, "Use 'proxy_ob --help' for usage.\n")
		os.Exit(1)
	}
}

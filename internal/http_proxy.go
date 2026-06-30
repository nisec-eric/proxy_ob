package internal

import (
	"bufio"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
)

func ReadHTTPProxyRequest(br *bufio.Reader) (host string, port uint16, isConnect bool, initialData []byte, err error) {
	line, err := readLine(br)
	if err != nil {
		return "", 0, false, nil, fmt.Errorf("read request line: %w", err)
	}

	parts := strings.Fields(line)
	if len(parts) != 3 {
		return "", 0, false, nil, fmt.Errorf("malformed request line: %q", line)
	}

	method, target, proto := parts[0], parts[1], parts[2]

	if method == "CONNECT" {
		h, pStr, splitErr := net.SplitHostPort(target)
		if splitErr != nil {
			return "", 0, false, nil, fmt.Errorf("parse CONNECT target: %w", splitErr)
		}
		p, parseErr := strconv.ParseUint(pStr, 10, 16)
		if parseErr != nil {
			return "", 0, false, nil, fmt.Errorf("parse CONNECT port: %w", parseErr)
		}

		if err := consumeHeaders(br); err != nil {
			return "", 0, false, nil, fmt.Errorf("read CONNECT headers: %w", err)
		}

		return h, uint16(p), true, nil, nil
	}

	u, parseErr := url.Parse(target)
	if parseErr != nil {
		return "", 0, false, nil, fmt.Errorf("parse request URI: %w", parseErr)
	}

	host = u.Hostname()
	if host == "" {
		return "", 0, false, nil, fmt.Errorf("missing host in request URI")
	}

	port = 80
	if u.Port() != "" {
		p, err := strconv.ParseUint(u.Port(), 10, 16)
		if err != nil {
			return "", 0, false, nil, fmt.Errorf("invalid port %q: %w", u.Port(), err)
		}
		port = uint16(p)
	}

	headers, headersErr := readHeaders(br)
	if headersErr != nil {
		return "", 0, false, nil, fmt.Errorf("read headers: %w", headersErr)
	}

	rewritten := method + " " + u.RequestURI() + " " + proto + "\r\n" + headers

	return host, port, false, []byte(rewritten), nil
}

func readLine(br *bufio.Reader) (string, error) {
	line, err := br.ReadString('\n')
	if err != nil {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}

const maxHeaderLines = 100

func consumeHeaders(br *bufio.Reader) error {
	for i := 0; i < maxHeaderLines; i++ {
		line, err := readLine(br)
		if err != nil {
			return err
		}
		if line == "" {
			return nil
		}
	}
	return fmt.Errorf("too many header lines (limit %d)", maxHeaderLines)
}

func readHeaders(br *bufio.Reader) (string, error) {
	var sb strings.Builder
	for i := 0; i < maxHeaderLines; i++ {
		line, err := readLine(br)
		if err != nil {
			return "", err
		}
		sb.WriteString(line)
		sb.WriteString("\r\n")
		if line == "" {
			return sb.String(), nil
		}
	}
	return "", fmt.Errorf("too many header lines (limit %d)", maxHeaderLines)
}

func SendHTTPResponse(conn net.Conn, statusCode int, statusText string) error {
	response := fmt.Sprintf("HTTP/1.1 %d %s\r\n\r\n", statusCode, statusText)
	_, err := conn.Write([]byte(response))
	return err
}

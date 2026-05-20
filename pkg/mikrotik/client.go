package mikrotik

import (
	"fmt"
	"net"
	"strings"

	routeros "github.com/go-routeros/routeros/v3"
)

// resolveAPIAddress accepts a router address that may or may not carry an
// explicit API port and returns a valid "host:port" string for routeros.Dial.
//
// MikroTik's API port is configurable (default 8728 plaintext, 8729 TLS). When
// operators store the router endpoint as "1.2.3.4:9291" we must dial that port
// instead of blindly appending 8728. Inputs handled:
//
//   - "1.2.3.4"        → "1.2.3.4:<default>"
//   - "1.2.3.4:9291"   → "1.2.3.4:9291"
//   - "[::1]"          → "[::1]:<default>"
//   - "[::1]:8728"     → "[::1]:8728"
//   - "host.example"   → "host.example:<default>"
func resolveAPIAddress(address string, defaultPort int) string {
	addr := strings.TrimSpace(address)
	if addr == "" {
		return fmt.Sprintf(":%d", defaultPort)
	}
	if _, _, err := net.SplitHostPort(addr); err == nil {
		return addr
	}
	// Bare IPv6 without brackets — wrap so SplitHostPort works downstream.
	if ip := net.ParseIP(addr); ip != nil && strings.Contains(addr, ":") {
		return fmt.Sprintf("[%s]:%d", addr, defaultPort)
	}
	return fmt.Sprintf("%s:%d", addr, defaultPort)
}

type Command struct {
	Path   string
	Params map[string]string
}

type Client struct {
	conn *routeros.Client
	isV7 bool
}

func NewClient(address, username, password string, isV7 bool) (*Client, error) {
	addr := resolveAPIAddress(address, 8728)
	conn, err := routeros.Dial(addr, username, password)
	if err != nil {
		return nil, fmt.Errorf("dial routeros %s: %w", addr, err)
	}
	return &Client{conn: conn, isV7: isV7}, nil
}

func (c *Client) Close() {
	if c.conn != nil {
		c.conn.Close()
	}
}

func (c *Client) RunCommand(cmd Command) error {
	args := []string{cmd.Path}
	for k, v := range cmd.Params {
		args = append(args, fmt.Sprintf("=%s=%s", k, v))
	}

	_, err := c.conn.RunArgs(args)
	if err != nil {
		return fmt.Errorf("run %s: %w", cmd.Path, err)
	}
	return nil
}

func (c *Client) Run(path string, params map[string]string) ([]map[string]string, error) {
	args := []string{path}
	for k, v := range params {
		// Query parameters start with ?, set parameters start with =
		if k[0] == '?' {
			args = append(args, fmt.Sprintf("%s=%s", k, v))
		} else {
			args = append(args, fmt.Sprintf("=%s=%s", k, v))
		}
	}

	reply, err := c.conn.RunArgs(args)
	if err != nil {
		return nil, fmt.Errorf("run %s: %w", path, err)
	}

	var results []map[string]string
	for _, re := range reply.Re {
		results = append(results, re.Map)
	}
	return results, nil
}

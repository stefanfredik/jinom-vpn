package mikrotik

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	routeros "github.com/go-routeros/routeros/v3"
)

// defaultDialTimeout adalah batas waktu konek TCP+login ke RouterOS API.
// Linux TCP default (~2 menit) tidak bisa diterima untuk operasi cleanup yang
// dipanggil sinkron oleh DELETE handler — operator menunggu HTTP respons.
// Pilihan 10s: cukup untuk router lambat di tautan internet tipis, tidak
// terlalu agresif untuk koneksi pertama yang butuh handshake TLS/IPsec.
const defaultDialTimeout = 10 * time.Second

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

// NewClient dials a RouterOS API. apiPort is the default port used when the
// address does not already carry a "host:port" suffix; an explicit port in the
// address (e.g. "1.2.3.4:9291") always wins to preserve the legacy override.
// Pass 0 to fall back to the RouterOS plaintext default (8728).
func NewClient(address string, apiPort int, username, password string, isV7 bool) (*Client, error) {
	return NewClientWithTimeout(address, apiPort, username, password, isV7, defaultDialTimeout)
}

// NewClientWithTimeout sama dengan NewClient tetapi caller menentukan timeout
// dial+login secara eksplisit. Dipakai oleh test dan oleh path khusus yang
// punya konteks deadline berbeda (cleanup synchronous vs. provisioning).
func NewClientWithTimeout(address string, apiPort int, username, password string, isV7 bool, timeout time.Duration) (*Client, error) {
	if apiPort <= 0 || apiPort > 65535 {
		apiPort = 8728
	}
	addr := resolveAPIAddress(address, apiPort)
	conn, err := routeros.DialTimeout(addr, username, password, timeout)
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

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	_, err := c.conn.RunArgsContext(ctx, args)
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

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	reply, err := c.conn.RunArgsContext(ctx, args)
	if err != nil {
		return nil, fmt.Errorf("run %s: %w", path, err)
	}

	var results []map[string]string
	for _, re := range reply.Re {
		results = append(results, re.Map)
	}
	return results, nil
}

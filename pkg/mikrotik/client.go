package mikrotik

import (
	"fmt"

	"gopkg.in/routeros.v2"
)

type Command struct {
	Path   string
	Params map[string]string
}

type Client struct {
	conn  *routeros.Client
	isV7  bool
}

func NewClient(address, username, password string, isV7 bool) (*Client, error) {
	addr := fmt.Sprintf("%s:8728", address)
	conn, err := routeros.Dial(addr, username, password)
	if err != nil {
		return nil, fmt.Errorf("dial routeros %s: %w", address, err)
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
		args = append(args, fmt.Sprintf("=%s=%s", k, v))
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

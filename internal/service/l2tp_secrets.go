package service

import (
	"fmt"
	"os"
	"strings"

	"github.com/jinom/vpn/internal/domain/tunnel"
)

func (s *L2TPService) updateChapSecrets(t *tunnel.ResellerTunnel) error {
	_ = s.removeChapSecrets(t.Namespace)

	nsIPNoMask := stripCIDR(t.ClientIPAddress)
	line := fmt.Sprintf("\"%s\" * \"%s\" %s # jinom-vpn: %s\n", t.L2TPUsername, t.L2TPPassword, nsIPNoMask, t.Namespace)

	f, err := os.OpenFile("/etc/ppp/chap-secrets", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer f.Close()

	_, err = f.WriteString(line)
	return err
}

func (s *L2TPService) removeChapSecrets(ns string) error {
	path := "/etc/ppp/chap-secrets"
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}

	lines := strings.Split(string(data), "\n")
	var newLines []string
	tag := fmt.Sprintf("# jinom-vpn: %s", ns)

	for _, line := range lines {
		if line != "" && !strings.Contains(line, tag) {
			newLines = append(newLines, line)
		}
	}

	content := strings.Join(newLines, "\n")
	if content != "" {
		content += "\n"
	}

	return os.WriteFile(path, []byte(content), 0600)
}

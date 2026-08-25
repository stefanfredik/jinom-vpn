package service

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"go.uber.org/zap"
)

func (s *TunnelService) CreateNOCTechnician(ctx context.Context, name string) (string, string, error) {
	if name == "" {
		return "", "", fmt.Errorf("technician name cannot be empty")
	}

	s.nocMu.Lock()
	defer s.nocMu.Unlock()

	privBytes, err := exec.Command("wg", "genkey").Output()
	if err != nil {
		return "", "", fmt.Errorf("generate private key: %w", err)
	}
	clientPriv := strings.TrimSpace(string(privBytes))

	cmd := exec.Command("wg", "pubkey")
	cmd.Stdin = strings.NewReader(clientPriv + "\n")
	pubBytes, err := cmd.Output()
	if err != nil {
		return "", "", fmt.Errorf("generate public key: %w", err)
	}
	clientPub := strings.TrimSpace(string(pubBytes))

	serverPubBytes, err := exec.Command("wg", "show", "wg-noc", "public-key").Output()
	if err != nil {
		return "", "", fmt.Errorf("fetch server public key: %w", err)
	}
	serverPub := strings.TrimSpace(string(serverPubBytes))

	clientIP, _, err := getNextFreeIP()
	if err != nil {
		return "", "", err
	}

	if err := appendPeerToConfig(name, clientPub, clientIP); err != nil {
		return "", "", err
	}

	if err := exec.Command("wg", "set", "wg-noc", "peer", clientPub, "allowed-ips", clientIP+"/32").Run(); err != nil {
		return "", "", fmt.Errorf("apply wireguard peer: %w", err)
	}

	clientConfig := fmt.Sprintf(`[Interface]
PrivateKey = %s
Address = %s/24
DNS = 8.8.8.8

[Peer]
PublicKey = %s
AllowedIPs = 10.50.0.0/24, 10.250.0.0/16, 10.254.0.0/16, 192.168.0.0/16, 172.16.0.0/12, 10.0.0.0/8, 100.64.0.0/10
Endpoint = %s:51820
PersistentKeepalive = 25
`, clientPriv, clientIP, serverPub, s.vpsPublicIP)

	return clientIP, clientConfig, nil
}

func (s *TunnelService) ListNOCTechnicians(ctx context.Context) ([]NOCUser, error) {
	s.nocMu.Lock()
	defer s.nocMu.Unlock()

	data, err := os.ReadFile("/etc/wireguard/wg-noc.conf")
	if err != nil {
		return nil, fmt.Errorf("read wg-noc.conf: %w", err)
	}

	activePeers := make(map[string]NOCUser)
	if out, err := exec.Command("wg", "show", "wg-noc", "dump").Output(); err == nil {
		for _, line := range strings.Split(string(out), "\n") {
			fields := strings.Fields(line)
			if len(fields) >= 8 {
				pubKey := fields[0]
				handshake, _ := strconv.ParseInt(fields[4], 10, 64)
				rx, _ := strconv.ParseInt(fields[5], 10, 64)
				tx, _ := strconv.ParseInt(fields[6], 10, 64)
				status := "offline"
				if handshake > 0 && time.Now().Unix()-handshake < 180 {
					status = "online"
				}
				activePeers[pubKey] = NOCUser{
					PublicKey: pubKey, LatestHandshake: handshake,
					TransferRx: rx, TransferTx: tx, Status: status,
				}
			}
		}
	}

	return parseNOCUsersFromConfig(string(data), activePeers), nil
}

func parseNOCUsersFromConfig(data string, activePeers map[string]NOCUser) []NOCUser {
	var users []NOCUser
	var current NOCUser
	inPeer := false

	for _, line := range strings.Split(data, "\n") {
		line = strings.TrimSpace(line)
		if line == "[Peer]" {
			if inPeer && current.PublicKey != "" {
				users = append(users, enrichNOCUser(current, activePeers))
			}
			current = NOCUser{}
			inPeer = true
			continue
		}
		if inPeer {
			if strings.HasPrefix(line, "#") {
				current.Name = strings.TrimSpace(strings.TrimPrefix(line, "#"))
			} else if strings.HasPrefix(line, "PublicKey") {
				parts := strings.SplitN(line, "=", 2)
				if len(parts) == 2 {
					current.PublicKey = strings.TrimSpace(parts[1])
				}
			} else if strings.HasPrefix(line, "AllowedIPs") {
				parts := strings.SplitN(line, "=", 2)
				if len(parts) == 2 {
					current.IP = strings.Split(strings.TrimSpace(parts[1]), "/")[0]
				}
			}
		}
	}
	if inPeer && current.PublicKey != "" {
		users = append(users, enrichNOCUser(current, activePeers))
	}
	return users
}

func enrichNOCUser(u NOCUser, active map[string]NOCUser) NOCUser {
	if a, ok := active[u.PublicKey]; ok {
		u.LatestHandshake = a.LatestHandshake
		u.TransferTx = a.TransferTx
		u.TransferRx = a.TransferRx
		u.Status = a.Status
	} else {
		u.Status = "offline"
	}
	return u
}

func (s *TunnelService) DeleteNOCTechnician(ctx context.Context, publicKey string) error {
	if publicKey == "" {
		return fmt.Errorf("public key cannot be empty")
	}

	s.nocMu.Lock()
	defer s.nocMu.Unlock()

	data, err := os.ReadFile("/etc/wireguard/wg-noc.conf")
	if err != nil {
		return fmt.Errorf("read config: %w", err)
	}

	output := removePeerFromConfig(string(data), publicKey)
	confPath := "/etc/wireguard/wg-noc.conf"
	tmpPath := confPath + ".tmp"
	if err := os.WriteFile(tmpPath, []byte(output), 0600); err != nil {
		return fmt.Errorf("write temp config: %w", err)
	}
	if err := os.Rename(tmpPath, confPath); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("atomic rename config: %w", err)
	}

	_ = exec.Command("wg", "set", "wg-noc", "peer", publicKey, "remove").Run()
	s.log.Info("Deleted NOC technician WireGuard peer", zap.String("public_key", publicKey))
	return nil
}

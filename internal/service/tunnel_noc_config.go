package service

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

func appendPeerToConfig(name, clientPub, clientIP string) error {
	confPath := "/etc/wireguard/wg-noc.conf"
	tmpPath := confPath + ".tmp"

	data, err := os.ReadFile(confPath)
	if err != nil {
		return fmt.Errorf("read wg-noc.conf: %w", err)
	}

	peerEntry := fmt.Sprintf("\n[Peer]\n# %s\nPublicKey = %s\nAllowedIPs = %s/32\n", name, clientPub, clientIP)
	updated := string(data) + peerEntry

	if err := os.WriteFile(tmpPath, []byte(updated), 0600); err != nil {
		return fmt.Errorf("write temp config: %w", err)
	}
	if err := os.Rename(tmpPath, confPath); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("atomic rename config: %w", err)
	}
	return nil
}

func removePeerFromConfig(data, publicKey string) string {
	lines := strings.Split(data, "\n")
	var newLines, peerLines []string
	inPeer, isTargetPeer := false, false

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "[Peer]" {
			if inPeer && !isTargetPeer {
				newLines = append(newLines, peerLines...)
			}
			inPeer = true
			isTargetPeer = false
			peerLines = []string{line}
			continue
		}
		if inPeer {
			peerLines = append(peerLines, line)
			if strings.Contains(trimmed, publicKey) {
				isTargetPeer = true
			}
		} else {
			newLines = append(newLines, line)
		}
	}
	if inPeer && !isTargetPeer {
		newLines = append(newLines, peerLines...)
	}

	output := strings.Join(newLines, "\n")
	for strings.Contains(output, "\n\n\n") {
		output = strings.ReplaceAll(output, "\n\n\n", "\n\n")
	}
	return output
}

func getNextFreeIP() (string, int, error) {
	data, err := os.ReadFile("/etc/wireguard/wg-noc.conf")
	if err != nil {
		return "", 0, fmt.Errorf("read wg-noc.conf: %w", err)
	}

	used := make(map[int]bool)
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "AllowedIPs") {
			parts := strings.Split(line, "=")
			if len(parts) == 2 {
				ipVal := strings.TrimSpace(parts[1])
				ipVal = strings.Split(ipVal, "/")[0]
				ipParts := strings.Split(ipVal, ".")
				if len(ipParts) == 4 && ipParts[0] == "10" && ipParts[1] == "50" && ipParts[2] == "0" {
					if octet, err := strconv.Atoi(ipParts[3]); err == nil {
						used[octet] = true
					}
				}
			}
		}
	}

	for i := 2; i <= 254; i++ {
		if !used[i] {
			return fmt.Sprintf("10.50.0.%d", i), i, nil
		}
	}
	return "", 0, fmt.Errorf("no free IP addresses left in 10.50.0.0/24 range")
}

func (s *TunnelService) findVPNIPByEndpointIP(endpointIP string) string {
	out, err := exec.Command("wg", "show", "wg-noc", "dump").Output()
	if err != nil {
		return ""
	}
	return parseVPNIPFromDump(string(out), endpointIP)
}

func parseVPNIPFromDump(dumpOutput, endpointIP string) string {
	endpointIP = strings.TrimSpace(endpointIP)
	if endpointIP == "" {
		return ""
	}

	type peerCandidate struct {
		vpnIP     string
		handshake int64
	}

	var candidates []peerCandidate

	for _, line := range strings.Split(dumpOutput, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}
		endpoint := fields[2]
		allowedIPs := fields[3]
		if endpoint == "(none)" || endpoint == "" {
			continue
		}
		host := endpoint
		if h, _, err := net.SplitHostPort(endpoint); err == nil {
			host = h
		}
		if host == endpointIP {
			vpnParts := strings.Split(allowedIPs, "/")
			if len(vpnParts) > 0 {
				ip := strings.TrimSpace(strings.Split(vpnParts[0], ",")[0])
				handshake, _ := strconv.ParseInt(fields[4], 10, 64)
				candidates = append(candidates, peerCandidate{
					vpnIP:     ip,
					handshake: handshake,
				})
			}
		}
	}

	if len(candidates) == 0 {
		return ""
	}

	best := candidates[0]
	for _, c := range candidates[1:] {
		if c.handshake > best.handshake {
			best = c
		}
	}
	return best.vpnIP
}

func netSplitLines(s string) []string {
	return strings.Split(s, "\n")
}

func isTechnicianTableRule(line string) bool {
	fromIP, tableID := extractRuleFields(line)
	if fromIP == "" || tableID == "" {
		return false
	}
	tid, err := strconv.Atoi(tableID)
	if err != nil {
		return false
	}
	return tid >= 10000 && tid <= 59999
}

func containsLookup(line string) bool {
	return isTechnicianTableRule(line)
}

func extractRuleFields(line string) (fromIP, tableID string) {
	fields := strings.Fields(line)
	for i, field := range fields {
		if field == "from" && i+1 < len(fields) {
			fromIP = fields[i+1]
		}
		if field == "lookup" && i+1 < len(fields) {
			tableID = fields[i+1]
		}
	}
	return fromIP, tableID
}

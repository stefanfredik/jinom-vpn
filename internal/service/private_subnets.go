package service

// defaultPrivateSubnets is the list of RFC-1918 private IP ranges used as a
// fallback when no MonitoringSubnets are explicitly configured on a tunnel.
// All traffic destined for these ranges will be routed through the VPN tunnel,
// which is safe because each company is isolated in its own network namespace.
var defaultPrivateSubnets = []string{
	"10.0.0.0/8",
	"172.16.0.0/12",
	"192.168.0.0/16",
}

// effectiveSubnets mengembalikan default private subnets RFC-1918 yang digabung
// dengan subnet kustom/IP publik yang dimasukkan operator.
// Dengan demikian, IP private selalu aktif secara otomatis dan operator hanya perlu
// memasukkan IP publik/subnet tambahan tanpa menginput ulang RFC-1918.
func effectiveSubnets(monitoringSubnets []string) []string {
	result := make([]string, 0, len(defaultPrivateSubnets)+len(monitoringSubnets))
	seen := make(map[string]bool)

	for _, s := range defaultPrivateSubnets {
		result = append(result, s)
		seen[s] = true
	}

	for _, s := range monitoringSubnets {
		if !seen[s] {
			result = append(result, s)
			seen[s] = true
		}
	}

	return result
}

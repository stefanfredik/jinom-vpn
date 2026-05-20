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

// effectiveSubnets returns the tunnel's MonitoringSubnets if set, otherwise
// falls back to all RFC-1918 private ranges.
func effectiveSubnets(monitoringSubnets []string) []string {
	if len(monitoringSubnets) > 0 {
		return monitoringSubnets
	}
	return defaultPrivateSubnets
}

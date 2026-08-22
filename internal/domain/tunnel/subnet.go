package tunnel

import (
	"fmt"
	"net"
	"strings"
)

// NormalizeSubnets validates and canonicalizes the monitoring subnet list.
// Returns a clean list of canonical CIDRs without duplicates.
// Subnets encompassing the VPS public IP are rejected to prevent routing hijacking.
func NormalizeSubnets(subnets []string, vpsPublicIP string) ([]string, error) {
	out := make([]string, 0, len(subnets))
	seen := make(map[string]struct{}, len(subnets))

	for _, raw := range subnets {
		s := strings.TrimSpace(raw)
		if s == "" {
			continue
		}

		canonical, err := canonicalizeCIDR(s)
		if err != nil {
			return nil, err
		}
		if _, dup := seen[canonical]; dup {
			continue
		}
		if err := rejectDangerousSubnet(canonical, vpsPublicIP); err != nil {
			return nil, err
		}

		seen[canonical] = struct{}{}
		out = append(out, canonical)
	}

	return out, nil
}

// canonicalizeCIDR converts an IP string into canonical CIDR form (e.g. "192.168.1.5/24" -> "192.168.1.0/24").
func canonicalizeCIDR(s string) (string, error) {
	ip, ipNet, err := net.ParseCIDR(s)
	if err != nil {
		return "", fmt.Errorf("%w: %q is not a valid CIDR (e.g. 192.168.1.0/24)", ErrInvalidSubnet, s)
	}
	if ip.To4() == nil {
		return "", fmt.Errorf("%w: %q is IPv6, only IPv4 is currently supported", ErrInvalidSubnet, s)
	}
	return ipNet.String(), nil
}

// rejectDangerousSubnet rejects default routes and routes containing VPS public IP.
func rejectDangerousSubnet(cidr, vpsPublicIP string) error {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return fmt.Errorf("%w: %q", ErrInvalidSubnet, cidr)
	}

	if ones, _ := ipNet.Mask.Size(); ones == 0 {
		return fmt.Errorf("%w: %q is a default route and would disrupt VPS connectivity", ErrInvalidSubnet, cidr)
	}

	if vpsPublicIP != "" {
		if vpsIP := net.ParseIP(vpsPublicIP); vpsIP != nil && ipNet.Contains(vpsIP) {
			return fmt.Errorf("%w: %q encompasses VPS public IP (%s) and would break server management traffic",
				ErrInvalidSubnet, cidr, vpsPublicIP)
		}
	}

	return nil
}

// DiffSubnets computes added and removed subnets between oldSubnets and newSubnets.
func DiffSubnets(oldSubnets, newSubnets []string) (added, removed []string) {
	oldSet := make(map[string]struct{}, len(oldSubnets))
	for _, s := range oldSubnets {
		oldSet[s] = struct{}{}
	}
	newSet := make(map[string]struct{}, len(newSubnets))
	for _, s := range newSubnets {
		newSet[s] = struct{}{}
	}

	for _, s := range newSubnets {
		if _, ok := oldSet[s]; !ok {
			added = append(added, s)
		}
	}
	for _, s := range oldSubnets {
		if _, ok := newSet[s]; !ok {
			removed = append(removed, s)
		}
	}
	return added, removed
}

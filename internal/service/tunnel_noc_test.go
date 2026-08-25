package service

import (
	"testing"
)

func TestParseVPNIPFromDump(t *testing.T) {
	dump := `mH3GAuPnf6STR65nyn/7DHZtdkGbc57NXiAD0gsh/VM=	Ripu7l8dtFm+Pgkea5LxrJw4nEGduM9vaQ08qlt0vyc=	51820	off
WneSptw5embXYIbUm4OE/eCDFiaH1U7RJrGu/oAIoQo=	(none)	103.122.65.200:64672	10.50.0.2/32	1787628798	89769088	1453163808	off
Oa1ngzizhDtvF/YCbA+ysys82Z3AdT/O6B6mELUxtQs=	(none)	103.122.65.230:49498	10.50.0.5/32	1786600909	343580	3929820	off
zGQ4ctDyNftLO+AAv+uzvhNI+fSmv2tCYtrvSJJ96Ds=	(none)	(none)	10.50.0.6/32	0	0	0	off
`

	tests := []struct {
		name       string
		endpointIP string
		expectedIP string
	}{
		{
			name:       "Match active peer with port",
			endpointIP: "103.122.65.200",
			expectedIP: "10.50.0.2",
		},
		{
			name:       "Match second peer",
			endpointIP: "103.122.65.230",
			expectedIP: "10.50.0.5",
		},
		{
			name:       "Unknown endpoint",
			endpointIP: "1.2.3.4",
			expectedIP: "",
		},
		{
			name:       "Empty endpoint",
			endpointIP: "",
			expectedIP: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseVPNIPFromDump(dump, tt.endpointIP)
			if got != tt.expectedIP {
				t.Errorf("parseVPNIPFromDump() = %v, want %v", got, tt.expectedIP)
			}
		})
	}

	dumpSharedNAT := `mH3GAuPnf6STR65nyn/7DHZtdkGbc57NXiAD0gsh/VM=	Ripu7l8dtFm+Pgkea5LxrJw4nEGduM9vaQ08qlt0vyc=	51820	off
PeerA=	(none)	103.122.65.200:64672	10.50.0.2/32	1787600000	100	100	off
PeerB=	(none)	103.122.65.200:54321	10.50.0.5/32	1787699999	200	200	off
`
	if got := parseVPNIPFromDump(dumpSharedNAT, "103.122.65.200"); got != "10.50.0.5" {
		t.Errorf("parseVPNIPFromDump() on shared NAT = %v, want 10.50.0.5 (newest handshake)", got)
	}
}

func TestIsTechnicianTableRule(t *testing.T) {
	tests := []struct {
		line     string
		expected bool
	}{
		{
			line:     "32765:	from 103.122.65.200 lookup 26840",
			expected: true,
		},
		{
			line:     "32764:	from 10.50.0.2 lookup 26840",
			expected: true,
		},
		{
			line:     "32763:	from 10.50.0.2 lookup 10002",
			expected: true,
		},
		{
			line:     "0:	from all lookup local",
			expected: false,
		},
		{
			line:     "220:	from all lookup 220",
			expected: false,
		},
		{
			line:     "32766:	from all lookup main",
			expected: false,
		},
		{
			line:     "32767:	from all lookup default",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.line, func(t *testing.T) {
			got := isTechnicianTableRule(tt.line)
			if got != tt.expected {
				t.Errorf("isTechnicianTableRule(%q) = %v, want %v", tt.line, got, tt.expected)
			}
		})
	}
}

func TestExtractRuleFields(t *testing.T) {
	line := "32765:	from 103.122.65.200 lookup 26840"
	fromIP, tableID := extractRuleFields(line)
	if fromIP != "103.122.65.200" || tableID != "26840" {
		t.Errorf("extractRuleFields(%q) = (%q, %q), want (103.122.65.200, 26840)", line, fromIP, tableID)
	}
}

func TestCalculateTableID(t *testing.T) {
	svc := &TunnelService{}
	tableID, err := svc.calculateTableID("103.122.65.200")
	if err != nil {
		t.Fatalf("calculateTableID failed: %v", err)
	}
	expected := "26840"
	if tableID != expected {
		t.Errorf("calculateTableID() = %v, want %v", tableID, expected)
	}

	_, err = svc.calculateTableID("invalid-ip")
	if err == nil {
		t.Errorf("calculateTableID with invalid IP should fail")
	}
}

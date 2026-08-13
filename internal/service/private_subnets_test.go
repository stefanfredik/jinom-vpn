package service

import (
	"reflect"
	"testing"

	"github.com/jinom/vpn/internal/domain/tunnel"
)

func TestEffectiveSubnets(t *testing.T) {
	tests := []struct {
		name     string
		input    []string
		expected []string
	}{
		{
			name:     "empty input includes RFC-1918 defaults",
			input:    nil,
			expected: []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"},
		},
		{
			name:     "custom public IP appended to RFC-1918 defaults",
			input:    []string{"203.0.113.50/32"},
			expected: []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "203.0.113.50/32"},
		},
		{
			name:     "duplicates with RFC-1918 defaults are deduplicated",
			input:    []string{"10.0.0.0/8", "1.1.1.1/32"},
			expected: []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "1.1.1.1/32"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := effectiveSubnets(tt.input)
			if !reflect.DeepEqual(got, tt.expected) {
				t.Errorf("effectiveSubnets(%v) = %v, want %v", tt.input, got, tt.expected)
			}
		})
	}
}

func TestEffectiveSubnetsDiffScenarios(t *testing.T) {
	tests := []struct {
		name        string
		oldSubnets  []string
		newSubnets  []string
		wantAdded   []string
		wantRemoved []string
	}{
		{
			name:        "adding public IP to empty config preserves RFC-1918 and adds only public IP",
			oldSubnets:  nil,
			newSubnets:  []string{"203.0.113.50/32"},
			wantAdded:   []string{"203.0.113.50/32"},
			wantRemoved: nil,
		},
		{
			name:        "adding second public IP adds only the new public IP",
			oldSubnets:  []string{"203.0.113.50/32"},
			newSubnets:  []string{"203.0.113.50/32", "198.51.100.10/32"},
			wantAdded:   []string{"198.51.100.10/32"},
			wantRemoved: nil,
		},
		{
			name:        "removing public IP removes only that public IP and keeps RFC-1918",
			oldSubnets:  []string{"203.0.113.50/32"},
			newSubnets:  nil,
			wantAdded:   nil,
			wantRemoved: []string{"203.0.113.50/32"},
		},
		{
			name:        "editing list to add custom subnet and remove another",
			oldSubnets:  []string{"203.0.113.50/32"},
			newSubnets:  []string{"198.51.100.10/32"},
			wantAdded:   []string{"198.51.100.10/32"},
			wantRemoved: []string{"203.0.113.50/32"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			oldEff := effectiveSubnets(tt.oldSubnets)
			newEff := effectiveSubnets(tt.newSubnets)

			added, removed := tunnel.DiffSubnets(oldEff, newEff)
			if !reflect.DeepEqual(added, tt.wantAdded) {
				t.Errorf("DiffSubnets added = %v, want %v", added, tt.wantAdded)
			}
			if !reflect.DeepEqual(removed, tt.wantRemoved) {
				t.Errorf("DiffSubnets removed = %v, want %v", removed, tt.wantRemoved)
			}
		})
	}
}

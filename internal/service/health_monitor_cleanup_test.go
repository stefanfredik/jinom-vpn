package service

import (
	"testing"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/jinom/vpn/internal/domain/tunnel"
)

func TestHealthMonitor_Forget(t *testing.T) {
	s := NewHealthMonitorService(nil, nil, nil, nil, "", zap.NewNop())

	id := "abc-123"
	_ = s.getState(id) // populate
	if _, ok := s.states[id]; !ok {
		t.Fatal("setup failed: state not populated")
	}

	s.Forget(id)
	if _, ok := s.states[id]; ok {
		t.Fatalf("state map still contains %s after Forget", id)
	}
}

func TestHealthMonitor_ForgetUnknownIDIsSafe(t *testing.T) {
	s := NewHealthMonitorService(nil, nil, nil, nil, "", zap.NewNop())
	// Should not panic, should not affect anything.
	s.Forget("does-not-exist")
}

func TestHealthMonitor_PurgeStale(t *testing.T) {
	s := NewHealthMonitorService(nil, nil, nil, nil, "", zap.NewNop())

	keepID := uuid.New()
	dropID := uuid.New()
	_ = s.getState(keepID.String())
	_ = s.getState(dropID.String())

	// Pretend keepID is still active; dropID was deleted.
	active := []tunnel.ResellerTunnel{{ID: keepID}}
	s.purgeStale(active)

	if _, ok := s.states[keepID.String()]; !ok {
		t.Errorf("kept ID %s was incorrectly purged", keepID)
	}
	if _, ok := s.states[dropID.String()]; ok {
		t.Errorf("dropped ID %s remained after purge", dropID)
	}
}

package tunnel

import (
	"context"

	"github.com/google/uuid"
)

type Repository interface {
	FindByID(ctx context.Context, id uuid.UUID) (*ResellerTunnel, error)
	FindAll(ctx context.Context, filter Filter) ([]ResellerTunnel, int64, error)
	FindByResellerID(ctx context.Context, resellerID int64) (*ResellerTunnel, error)
	FindByNamespace(ctx context.Context, namespace string) (*ResellerTunnel, error)
	FindActive(ctx context.Context) ([]ResellerTunnel, error)
	// FindActiveOrDown returns tunnels in 'active' OR 'down' state. The health
	// monitor uses this so a tunnel previously marked 'down' keeps being probed
	// and can transition back to 'active' once it recovers.
	FindActiveOrDown(ctx context.Context) ([]ResellerTunnel, error)
	NextTunnelIndex(ctx context.Context) (int, error)
	Save(ctx context.Context, t *ResellerTunnel) error
	UpdateStatus(ctx context.Context, id uuid.UUID, status Status, lastError string) error
	SaveMetric(ctx context.Context, metric *TunnelMetric) error
	GetMetrics(ctx context.Context, tunnelID uuid.UUID, limit int) ([]TunnelMetric, error)
	SaveStatusHistory(ctx context.Context, history *TunnelStatusHistory) error
	GetStatusHistory(ctx context.Context, tunnelID uuid.UUID, limit int) ([]TunnelStatusHistory, error)
	Delete(ctx context.Context, id uuid.UUID) error
}

type Filter struct {
	CompanyID  *int64
	ResellerID *int64
	Status     *Status
	Page       int
	Limit      int
}

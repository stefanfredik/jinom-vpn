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
	Save(ctx context.Context, t *ResellerTunnel) error
	UpdateStatus(ctx context.Context, id uuid.UUID, status Status, lastError string) error
	Delete(ctx context.Context, id uuid.UUID) error
}

type Filter struct {
	CompanyID  *int64
	ResellerID *int64
	Status     *Status
	Page       int
	Limit      int
}

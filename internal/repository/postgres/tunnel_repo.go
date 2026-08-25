package postgres

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/jinom/vpn/internal/domain/tunnel"
	"github.com/jinom/vpn/internal/platform/crypto"
	"github.com/jinom/vpn/internal/platform/database"
)

type TunnelRepository struct {
	db     *database.PostgresDB
	crypto *crypto.Crypto
	log    *zap.Logger
}

func NewTunnelRepository(db *database.PostgresDB, c *crypto.Crypto, log *zap.Logger) *TunnelRepository {
	return &TunnelRepository{db: db, crypto: c, log: log}
}

func (r *TunnelRepository) FindByID(ctx context.Context, id uuid.UUID) (*tunnel.ResellerTunnel, error) {
	var rec tunnelRecord
	err := r.db.DB.GetContext(ctx, &rec, `SELECT * FROM reseller_tunnels WHERE id = $1`, id)
	if err == sql.ErrNoRows {
		return nil, tunnel.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("find tunnel by id: %w", err)
	}
	return r.mapToDomain(&rec), nil
}

func (r *TunnelRepository) FindAll(ctx context.Context, f tunnel.Filter) ([]tunnel.ResellerTunnel, int64, error) {
	where := "WHERE 1=1"
	args := []interface{}{}
	argIdx := 1

	if f.CompanyID != nil {
		where += fmt.Sprintf(" AND company_id = $%d", argIdx)
		args = append(args, *f.CompanyID)
		argIdx++
	}
	if f.ResellerID != nil {
		where += fmt.Sprintf(" AND reseller_id = $%d", argIdx)
		args = append(args, *f.ResellerID)
		argIdx++
	}
	if f.Status != nil {
		where += fmt.Sprintf(" AND status = $%d", argIdx)
		args = append(args, string(*f.Status))
		argIdx++
	}

	var total int64
	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM reseller_tunnels %s", where)
	if err := r.db.DB.GetContext(ctx, &total, countQuery, args...); err != nil {
		return nil, 0, fmt.Errorf("count tunnels: %w", err)
	}

	if f.Limit <= 0 {
		f.Limit = 50
	}
	if f.Page <= 0 {
		f.Page = 1
	}
	offset := (f.Page - 1) * f.Limit

	query := fmt.Sprintf(
		"SELECT * FROM reseller_tunnels %s ORDER BY created_at DESC LIMIT $%d OFFSET $%d",
		where, argIdx, argIdx+1,
	)
	args = append(args, f.Limit, offset)

	var records []tunnelRecord
	if err := r.db.DB.SelectContext(ctx, &records, query, args...); err != nil {
		return nil, 0, fmt.Errorf("find all tunnels: %w", err)
	}

	tunnels := make([]tunnel.ResellerTunnel, len(records))
	for i := range records {
		tunnels[i] = *r.mapToDomain(&records[i])
	}
	return tunnels, total, nil
}

func (r *TunnelRepository) FindByResellerID(ctx context.Context, resellerID int64) (*tunnel.ResellerTunnel, error) {
	var rec tunnelRecord
	err := r.db.DB.GetContext(ctx, &rec, `SELECT * FROM reseller_tunnels WHERE reseller_id = $1 LIMIT 1`, resellerID)
	if err == sql.ErrNoRows {
		return nil, tunnel.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("find tunnel by reseller: %w", err)
	}
	return r.mapToDomain(&rec), nil
}

func (r *TunnelRepository) FindByNamespace(ctx context.Context, namespace string) (*tunnel.ResellerTunnel, error) {
	var rec tunnelRecord
	err := r.db.DB.GetContext(ctx, &rec, `SELECT * FROM reseller_tunnels WHERE namespace = $1`, namespace)
	if err == sql.ErrNoRows {
		return nil, tunnel.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("find tunnel by namespace: %w", err)
	}
	return r.mapToDomain(&rec), nil
}

func (r *TunnelRepository) FindByTunnelIndex(ctx context.Context, index int) (*tunnel.ResellerTunnel, error) {
	var rec tunnelRecord
	err := r.db.DB.GetContext(ctx, &rec, `SELECT * FROM reseller_tunnels WHERE tunnel_index = $1 LIMIT 1`, index)
	if err == sql.ErrNoRows {
		return nil, tunnel.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("find tunnel by index: %w", err)
	}
	return r.mapToDomain(&rec), nil
}

func (r *TunnelRepository) FindActive(ctx context.Context) ([]tunnel.ResellerTunnel, error) {
	var records []tunnelRecord
	err := r.db.DB.SelectContext(ctx, &records,
		`SELECT * FROM reseller_tunnels WHERE status = $1 ORDER BY created_at`, tunnel.StatusActive)
	if err != nil {
		return nil, fmt.Errorf("find active tunnels: %w", err)
	}

	tunnels := make([]tunnel.ResellerTunnel, len(records))
	for i := range records {
		tunnels[i] = *r.mapToDomain(&records[i])
	}
	return tunnels, nil
}

func (r *TunnelRepository) FindActiveOrDown(ctx context.Context) ([]tunnel.ResellerTunnel, error) {
	var records []tunnelRecord
	err := r.db.DB.SelectContext(ctx, &records,
		`SELECT * FROM reseller_tunnels WHERE status IN ($1, $2) ORDER BY created_at`,
		tunnel.StatusActive, tunnel.StatusDown)
	if err != nil {
		return nil, fmt.Errorf("find active-or-down tunnels: %w", err)
	}

	tunnels := make([]tunnel.ResellerTunnel, len(records))
	for i := range records {
		tunnels[i] = *r.mapToDomain(&records[i])
	}
	return tunnels, nil
}

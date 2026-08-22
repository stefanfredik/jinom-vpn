package postgres

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/jinom/vpn/internal/domain/tunnel"
)

func (r *TunnelRepository) Save(ctx context.Context, t *tunnel.ResellerTunnel) error {
	if t.ID == uuid.Nil {
		t.ID = uuid.New()
	}
	t.UpdatedAt = time.Now()

	rec := r.mapToRecord(t)

	query := `
		INSERT INTO reseller_tunnels (
			id, reseller_id, company_id, name, vpn_type, namespace, tunnel_index,
			server_public_key, server_private_key_enc, server_listen_port, server_ip_address,
			client_public_key, client_ip_address, client_endpoint,
			l2tp_username, l2tp_password_enc, psk_enc,
			router_ip, router_username, router_password_enc, routeros_version, router_api_port,
			monitoring_subnets, status, last_error, created_at, updated_at
		) VALUES (
			:id, :reseller_id, :company_id, :name, :vpn_type, :namespace, :tunnel_index,
			:server_public_key, :server_private_key_enc, :server_listen_port, :server_ip_address,
			:client_public_key, :client_ip_address, :client_endpoint,
			:l2tp_username, :l2tp_password_enc, :psk_enc,
			:router_ip, :router_username, :router_password_enc, :routeros_version, :router_api_port,
			:monitoring_subnets, :status, :last_error, :created_at, :updated_at
		)
		ON CONFLICT (id) DO UPDATE SET
			name = EXCLUDED.name,
			tunnel_index = EXCLUDED.tunnel_index,
			server_public_key = EXCLUDED.server_public_key,
			server_private_key_enc = EXCLUDED.server_private_key_enc,
			server_listen_port = EXCLUDED.server_listen_port,
			server_ip_address = EXCLUDED.server_ip_address,
			client_public_key = EXCLUDED.client_public_key,
			client_ip_address = EXCLUDED.client_ip_address,
			client_endpoint = EXCLUDED.client_endpoint,
			l2tp_username = EXCLUDED.l2tp_username,
			l2tp_password_enc = EXCLUDED.l2tp_password_enc,
			psk_enc = EXCLUDED.psk_enc,
			router_ip = EXCLUDED.router_ip,
			router_username = EXCLUDED.router_username,
			router_password_enc = EXCLUDED.router_password_enc,
			routeros_version = EXCLUDED.routeros_version,
			router_api_port = EXCLUDED.router_api_port,
			monitoring_subnets = EXCLUDED.monitoring_subnets,
			updated_at = EXCLUDED.updated_at`

	_, err := r.db.DB.NamedExecContext(ctx, query, rec)
	if err != nil {
		return fmt.Errorf("save tunnel: %w", err)
	}
	return nil
}

func (r *TunnelRepository) Delete(ctx context.Context, id uuid.UUID) error {
	_, err := r.db.DB.ExecContext(ctx, `DELETE FROM reseller_tunnels WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("delete tunnel: %w", err)
	}
	return nil
}

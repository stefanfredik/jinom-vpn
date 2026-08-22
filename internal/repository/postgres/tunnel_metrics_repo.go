package postgres

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"

	"github.com/jinom/vpn/internal/domain/tunnel"
)

func (r *TunnelRepository) UpdateSubnets(
	ctx context.Context,
	id uuid.UUID,
	subnets []string,
	expectedUpdatedAt time.Time,
) (time.Time, error) {
	var newUpdatedAt time.Time

	err := r.db.DB.QueryRowxContext(ctx, `
		UPDATE reseller_tunnels
		SET monitoring_subnets = $1, updated_at = NOW()
		WHERE id = $2 AND updated_at = $3
		RETURNING updated_at`,
		pq.StringArray(subnets), id, expectedUpdatedAt,
	).Scan(&newUpdatedAt)

	if err == nil {
		return newUpdatedAt, nil
	}
	if err != sql.ErrNoRows {
		return time.Time{}, fmt.Errorf("update subnets: %w", err)
	}

	var exists bool
	if e := r.db.DB.QueryRowxContext(ctx,
		`SELECT EXISTS(SELECT 1 FROM reseller_tunnels WHERE id = $1)`, id,
	).Scan(&exists); e != nil {
		return time.Time{}, fmt.Errorf("update subnets: check existence: %w", e)
	}
	if !exists {
		return time.Time{}, tunnel.ErrNotFound
	}
	return time.Time{}, tunnel.ErrConflict
}

func (r *TunnelRepository) UpdateStatus(ctx context.Context, id uuid.UUID, status tunnel.Status, lastError string) error {
	_, err := r.db.DB.ExecContext(ctx,
		`UPDATE reseller_tunnels SET status = $1, last_error = $2, updated_at = NOW() WHERE id = $3`,
		string(status), sql.NullString{String: lastError, Valid: lastError != ""}, id,
	)
	if err != nil {
		return fmt.Errorf("update tunnel status: %w", err)
	}
	return nil
}

func (r *TunnelRepository) SaveMetric(ctx context.Context, metric *tunnel.TunnelMetric) error {
	query := `
		INSERT INTO tunnel_metrics (tunnel_id, timestamp, latency_ms, packet_loss, rx_bytes, tx_bytes, handshake_time)
		VALUES (:tunnel_id, :timestamp, :latency_ms, :packet_loss, :rx_bytes, :tx_bytes, :handshake_time)
	`
	_, err := r.db.DB.NamedExecContext(ctx, query, map[string]interface{}{
		"tunnel_id":      metric.TunnelID,
		"timestamp":      metric.Timestamp,
		"latency_ms":     metric.LatencyMS,
		"packet_loss":    metric.PacketLoss,
		"rx_bytes":       metric.RxBytes,
		"tx_bytes":       metric.TxBytes,
		"handshake_time": metric.HandshakeTime,
	})
	if err != nil {
		return fmt.Errorf("save tunnel metric: %w", err)
	}
	return nil
}

func (r *TunnelRepository) SaveStatusHistory(ctx context.Context, history *tunnel.TunnelStatusHistory) error {
	if history.ID == uuid.Nil {
		history.ID = uuid.New()
	}
	if history.CreatedAt.IsZero() {
		history.CreatedAt = time.Now()
	}

	query := `
		INSERT INTO tunnel_status_history (id, tunnel_id, status, reason, created_at)
		VALUES (:id, :tunnel_id, :status, :reason, :created_at)
	`
	_, err := r.db.DB.NamedExecContext(ctx, query, map[string]interface{}{
		"id":         history.ID,
		"tunnel_id":  history.TunnelID,
		"status":     string(history.Status),
		"reason":     history.Reason,
		"created_at": history.CreatedAt,
	})
	if err != nil {
		return fmt.Errorf("save tunnel status history: %w", err)
	}
	return nil
}

func (r *TunnelRepository) GetMetrics(ctx context.Context, tunnelID uuid.UUID, limit int) ([]tunnel.TunnelMetric, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	query := `
		SELECT tunnel_id, timestamp, latency_ms, packet_loss, rx_bytes, tx_bytes, handshake_time
		FROM tunnel_metrics
		WHERE tunnel_id = $1
		ORDER BY timestamp DESC
		LIMIT $2
	`
	rows, err := r.db.DB.QueryContext(ctx, query, tunnelID, limit)
	if err != nil {
		return nil, fmt.Errorf("get tunnel metrics: %w", err)
	}
	defer rows.Close()

	var metrics []tunnel.TunnelMetric
	for rows.Next() {
		var m tunnel.TunnelMetric
		var latencyMS, packetLoss sql.NullFloat64
		var rxBytes, txBytes sql.NullInt64
		var handshakeTime sql.NullTime

		if err := rows.Scan(&m.TunnelID, &m.Timestamp, &latencyMS, &packetLoss, &rxBytes, &txBytes, &handshakeTime); err != nil {
			return nil, err
		}

		if latencyMS.Valid {
			v := latencyMS.Float64
			m.LatencyMS = &v
		}
		if packetLoss.Valid {
			v := packetLoss.Float64
			m.PacketLoss = &v
		}
		if rxBytes.Valid {
			v := rxBytes.Int64
			m.RxBytes = &v
		}
		if txBytes.Valid {
			v := txBytes.Int64
			m.TxBytes = &v
		}
		if handshakeTime.Valid {
			v := handshakeTime.Time
			m.HandshakeTime = &v
		}

		metrics = append(metrics, m)
	}
	return metrics, nil
}

func (r *TunnelRepository) GetStatusHistory(ctx context.Context, tunnelID uuid.UUID, limit int) ([]tunnel.TunnelStatusHistory, error) {
	if limit <= 0 || limit > 1000 {
		limit = 50
	}
	query := `
		SELECT id, tunnel_id, status, reason, created_at
		FROM tunnel_status_history
		WHERE tunnel_id = $1
		ORDER BY created_at DESC
		LIMIT $2
	`
	rows, err := r.db.DB.QueryContext(ctx, query, tunnelID, limit)
	if err != nil {
		return nil, fmt.Errorf("get tunnel status history: %w", err)
	}
	defer rows.Close()

	var history []tunnel.TunnelStatusHistory
	for rows.Next() {
		var h tunnel.TunnelStatusHistory
		var statusStr string
		var reason sql.NullString
		if err := rows.Scan(&h.ID, &h.TunnelID, &statusStr, &reason, &h.CreatedAt); err != nil {
			return nil, err
		}
		h.Status = tunnel.Status(statusStr)
		if reason.Valid {
			h.Reason = reason.String
		}
		history = append(history, h)
	}
	return history, nil
}

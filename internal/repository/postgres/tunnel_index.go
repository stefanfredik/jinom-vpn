package postgres

import (
	"context"
	"database/sql"
	"fmt"
)

// maxTunnelIndex is the largest index supported by indexToVethIPs / indexToSubnet.
// Derived from 256 octets * 64 subnets = 16384 (indices 1..16383).
const maxTunnelIndex = 16383

// tunnelIndexAdvisoryLock serializes concurrent index allocations across connections.
const tunnelIndexAdvisoryLock = 0x6a696e6f6d767061 // "jinomvpa"

// NextTunnelIndex allocates the lowest available tunnel_index in the range [1, 16383].
// It recycles freed indices left by deleted tunnels to avoid pool depletion.
func (r *TunnelRepository) NextTunnelIndex(ctx context.Context) (int, error) {
	tx, err := r.db.DB.BeginTxx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("next tunnel index: begin tx: %w", err)
	}
	defer tx.Rollback()

	// Serialize allocation across connections. Advisory lock releases on tx end.
	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock($1)`, int64(tunnelIndexAdvisoryLock)); err != nil {
		return 0, fmt.Errorf("next tunnel index: acquire advisory lock: %w", err)
	}

	// Find first available hole in range [1, maxTunnelIndex]
	query := `
		SELECT s.i
		FROM generate_series(1, $1) s(i)
		LEFT JOIN reseller_tunnels rt ON rt.tunnel_index = s.i
		WHERE rt.tunnel_index IS NULL
		ORDER BY s.i ASC
		LIMIT 1
	`
	var next int
	err = tx.GetContext(ctx, &next, query, maxTunnelIndex)
	if err == sql.ErrNoRows {
		return 0, fmt.Errorf("tunnel index pool exhausted: all %d indices are allocated", maxTunnelIndex)
	}
	if err != nil {
		return 0, fmt.Errorf("next tunnel index: query lowest free index: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("next tunnel index: commit: %w", err)
	}
	return next, nil
}

package postgres

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
	"go.uber.org/zap"

	"github.com/jinom/vpn/internal/domain/tunnel"
	"github.com/jinom/vpn/internal/platform/crypto"
	"github.com/jinom/vpn/internal/platform/database"
)

type tunnelRecord struct {
	ID         uuid.UUID `db:"id"`
	ResellerID int64     `db:"reseller_id"`
	CompanyID  int64     `db:"company_id"`
	Name       string    `db:"name"`
	VPNType    string    `db:"vpn_type"`
	Namespace  string    `db:"namespace"`

	ServerPublicKey    sql.NullString `db:"server_public_key"`
	ServerPrivateKeyEnc []byte        `db:"server_private_key_enc"`
	ServerListenPort   sql.NullInt32  `db:"server_listen_port"`
	ServerIPAddress    sql.NullString `db:"server_ip_address"`

	ClientPublicKey  sql.NullString `db:"client_public_key"`
	ClientIPAddress  sql.NullString `db:"client_ip_address"`
	ClientEndpoint   sql.NullString `db:"client_endpoint"`

	L2TPUsername    sql.NullString `db:"l2tp_username"`
	L2TPPasswordEnc []byte        `db:"l2tp_password_enc"`
	PSKEnc          []byte        `db:"psk_enc"`

	RouterIP          sql.NullString `db:"router_ip"`
	RouterUsername    sql.NullString `db:"router_username"`
	RouterPasswordEnc []byte        `db:"router_password_enc"`
	RouterOSVersion   int           `db:"routeros_version"`

	MonitoringSubnets pq.StringArray `db:"monitoring_subnets"`

	Status    string         `db:"status"`
	LastError sql.NullString `db:"last_error"`
	CreatedAt time.Time      `db:"created_at"`
	UpdatedAt time.Time      `db:"updated_at"`
}

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

func (r *TunnelRepository) Save(ctx context.Context, t *tunnel.ResellerTunnel) error {
	if t.ID == uuid.Nil {
		t.ID = uuid.New()
	}
	t.UpdatedAt = time.Now()

	rec := r.mapToRecord(t)

	query := `
		INSERT INTO reseller_tunnels (
			id, reseller_id, company_id, name, vpn_type, namespace,
			server_public_key, server_private_key_enc, server_listen_port, server_ip_address,
			client_public_key, client_ip_address, client_endpoint,
			l2tp_username, l2tp_password_enc, psk_enc,
			router_ip, router_username, router_password_enc, routeros_version,
			monitoring_subnets, status, last_error, created_at, updated_at
		) VALUES (
			:id, :reseller_id, :company_id, :name, :vpn_type, :namespace,
			:server_public_key, :server_private_key_enc, :server_listen_port, :server_ip_address,
			:client_public_key, :client_ip_address, :client_endpoint,
			:l2tp_username, :l2tp_password_enc, :psk_enc,
			:router_ip, :router_username, :router_password_enc, :routeros_version,
			:monitoring_subnets, :status, :last_error, :created_at, :updated_at
		)
		ON CONFLICT (id) DO UPDATE SET
			name = EXCLUDED.name,
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
			monitoring_subnets = EXCLUDED.monitoring_subnets,
			status = EXCLUDED.status,
			last_error = EXCLUDED.last_error,
			updated_at = EXCLUDED.updated_at`

	_, err := r.db.DB.NamedExecContext(ctx, query, rec)
	if err != nil {
		return fmt.Errorf("save tunnel: %w", err)
	}
	return nil
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

func (r *TunnelRepository) Delete(ctx context.Context, id uuid.UUID) error {
	_, err := r.db.DB.ExecContext(ctx, `DELETE FROM reseller_tunnels WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("delete tunnel: %w", err)
	}
	return nil
}

func (r *TunnelRepository) mapToDomain(rec *tunnelRecord) *tunnel.ResellerTunnel {
	t := &tunnel.ResellerTunnel{
		ID:              rec.ID,
		ResellerID:      rec.ResellerID,
		CompanyID:       rec.CompanyID,
		Name:            rec.Name,
		VPNType:         tunnel.VPNType(rec.VPNType),
		Namespace:       rec.Namespace,
		RouterOSVersion: rec.RouterOSVersion,
		Status:          tunnel.Status(rec.Status),
		CreatedAt:       rec.CreatedAt,
		UpdatedAt:       rec.UpdatedAt,
	}

	if rec.ServerPublicKey.Valid {
		t.ServerPublicKey = rec.ServerPublicKey.String
	}
	if rec.ServerListenPort.Valid {
		t.ServerListenPort = int(rec.ServerListenPort.Int32)
	}
	if rec.ServerIPAddress.Valid {
		t.ServerIPAddress = rec.ServerIPAddress.String
	}
	if rec.ClientPublicKey.Valid {
		t.ClientPublicKey = rec.ClientPublicKey.String
	}
	if rec.ClientIPAddress.Valid {
		t.ClientIPAddress = rec.ClientIPAddress.String
	}
	if rec.ClientEndpoint.Valid {
		t.ClientEndpoint = rec.ClientEndpoint.String
	}
	if rec.L2TPUsername.Valid {
		t.L2TPUsername = rec.L2TPUsername.String
	}
	if rec.RouterIP.Valid {
		t.RouterIP = rec.RouterIP.String
	}
	if rec.RouterUsername.Valid {
		t.RouterUsername = rec.RouterUsername.String
	}
	if rec.LastError.Valid {
		t.LastError = rec.LastError.String
	}
	if rec.MonitoringSubnets != nil {
		t.MonitoringSubnets = rec.MonitoringSubnets
	}

	r.decryptField(rec.ServerPrivateKeyEnc, &t.ServerPrivateKey)
	r.decryptField(rec.L2TPPasswordEnc, &t.L2TPPassword)
	r.decryptField(rec.PSKEnc, &t.PSK)
	r.decryptField(rec.RouterPasswordEnc, &t.RouterPassword)

	return t
}

func (r *TunnelRepository) mapToRecord(t *tunnel.ResellerTunnel) *tunnelRecord {
	rec := &tunnelRecord{
		ID:              t.ID,
		ResellerID:      t.ResellerID,
		CompanyID:       t.CompanyID,
		Name:            t.Name,
		VPNType:         string(t.VPNType),
		Namespace:       t.Namespace,
		RouterOSVersion: t.RouterOSVersion,
		Status:          string(t.Status),
		CreatedAt:       t.CreatedAt,
		UpdatedAt:       t.UpdatedAt,
		MonitoringSubnets: pq.StringArray(t.MonitoringSubnets),
	}

	rec.ServerPublicKey = toNullString(t.ServerPublicKey)
	rec.ServerListenPort = toNullInt32(t.ServerListenPort)
	rec.ServerIPAddress = toNullString(t.ServerIPAddress)
	rec.ClientPublicKey = toNullString(t.ClientPublicKey)
	rec.ClientIPAddress = toNullString(t.ClientIPAddress)
	rec.ClientEndpoint = toNullString(t.ClientEndpoint)
	rec.L2TPUsername = toNullString(t.L2TPUsername)
	rec.RouterIP = toNullString(t.RouterIP)
	rec.RouterUsername = toNullString(t.RouterUsername)
	rec.LastError = toNullString(t.LastError)

	rec.ServerPrivateKeyEnc = r.encryptField(t.ServerPrivateKey)
	rec.L2TPPasswordEnc = r.encryptField(t.L2TPPassword)
	rec.PSKEnc = r.encryptField(t.PSK)
	rec.RouterPasswordEnc = r.encryptField(t.RouterPassword)

	return rec
}

func (r *TunnelRepository) encryptField(value string) []byte {
	if value == "" {
		return nil
	}
	if r.crypto == nil {
		return []byte(value)
	}
	encrypted, err := r.crypto.Encrypt([]byte(value))
	if err != nil {
		r.log.Warn("failed to encrypt field", zap.Error(err))
		return []byte(value)
	}
	return []byte(encrypted)
}

func (r *TunnelRepository) decryptField(enc []byte, target *string) {
	if len(enc) == 0 {
		return
	}
	if r.crypto == nil {
		*target = string(enc)
		return
	}
	decrypted, err := r.crypto.Decrypt(string(enc))
	if err != nil {
		r.log.Warn("failed to decrypt field, using raw value", zap.Error(err))
		*target = string(enc)
		return
	}
	*target = string(decrypted)
}

func toNullString(s string) sql.NullString {
	return sql.NullString{String: s, Valid: s != ""}
}

func toNullInt32(v int) sql.NullInt32 {
	return sql.NullInt32{Int32: int32(v), Valid: v != 0}
}

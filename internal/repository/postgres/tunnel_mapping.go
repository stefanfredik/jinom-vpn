package postgres

import (
	"database/sql"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
	"go.uber.org/zap"

	"github.com/jinom/vpn/internal/domain/tunnel"
)

type tunnelRecord struct {
	ID          uuid.UUID     `db:"id"`
	ResellerID  int64         `db:"reseller_id"`
	CompanyID   int64         `db:"company_id"`
	Name        string        `db:"name"`
	VPNType     string        `db:"vpn_type"`
	Namespace   string        `db:"namespace"`
	TunnelIndex sql.NullInt32 `db:"tunnel_index"`

	ServerPublicKey     sql.NullString `db:"server_public_key"`
	ServerPrivateKeyEnc []byte         `db:"server_private_key_enc"`
	ServerListenPort    sql.NullInt32  `db:"server_listen_port"`
	ServerIPAddress     sql.NullString `db:"server_ip_address"`

	ClientPublicKey sql.NullString `db:"client_public_key"`
	ClientIPAddress sql.NullString `db:"client_ip_address"`
	ClientEndpoint  sql.NullString `db:"client_endpoint"`

	L2TPUsername    sql.NullString `db:"l2tp_username"`
	L2TPPasswordEnc []byte         `db:"l2tp_password_enc"`
	PSKEnc          []byte         `db:"psk_enc"`

	RouterIP          sql.NullString `db:"router_ip"`
	RouterUsername    sql.NullString `db:"router_username"`
	RouterPasswordEnc []byte         `db:"router_password_enc"`
	RouterOSVersion   int            `db:"routeros_version"`
	RouterAPIPort     int            `db:"router_api_port"`

	MonitoringSubnets pq.StringArray `db:"monitoring_subnets"`

	Status    string         `db:"status"`
	LastError sql.NullString `db:"last_error"`
	CreatedAt time.Time      `db:"created_at"`
	UpdatedAt time.Time      `db:"updated_at"`
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
		RouterAPIPort:   rec.RouterAPIPort,
		Status:          tunnel.Status(rec.Status),
		CreatedAt:       rec.CreatedAt,
		UpdatedAt:       rec.UpdatedAt,
	}
	if rec.TunnelIndex.Valid {
		t.TunnelIndex = int(rec.TunnelIndex.Int32)
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
		ID:                t.ID,
		ResellerID:        t.ResellerID,
		CompanyID:         t.CompanyID,
		Name:              t.Name,
		VPNType:           string(t.VPNType),
		Namespace:         t.Namespace,
		TunnelIndex:       toNullInt32(t.TunnelIndex),
		RouterOSVersion:   t.RouterOSVersion,
		RouterAPIPort:     t.EffectiveAPIPort(),
		Status:            string(t.Status),
		CreatedAt:         t.CreatedAt,
		UpdatedAt:         t.UpdatedAt,
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
		r.log.Warn("Failed to encrypt field", zap.Error(err))
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
		r.log.Warn("Failed to decrypt field, fallback to raw value", zap.Error(err))
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

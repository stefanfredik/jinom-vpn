package tunnel

import (
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
)

type Status string

const (
	StatusPending      Status = "pending"
	StatusProvisioning Status = "provisioning"
	StatusActive       Status = "active"
	StatusDown         Status = "down"
	StatusError        Status = "error"
	StatusDeleted      Status = "deleted"
)

type VPNType string

const (
	VPNTypeWireGuard VPNType = "wireguard"
	VPNTypeL2TP      VPNType = "l2tp"
)

var (
	ErrNotFound       = errors.New("tunnel not found")
	ErrInvalidName    = errors.New("tunnel name is required")
	ErrInvalidVPNType = errors.New("vpn_type must be 'wireguard' or 'l2tp'")
	ErrAlreadyActive  = errors.New("tunnel is already active")
	ErrNotActive      = errors.New("tunnel is not active")
)

type ResellerTunnel struct {
	ID         uuid.UUID
	ResellerID int64
	CompanyID  int64
	Name       string
	VPNType    VPNType
	Namespace  string

	ServerPublicKey  string
	ServerPrivateKey string
	ServerListenPort int
	ServerIPAddress  string

	ClientPublicKey  string
	ClientIPAddress  string
	ClientEndpoint   string

	L2TPUsername string
	L2TPPassword string
	PSK          string

	RouterIP       string
	RouterUsername string
	RouterPassword string
	RouterOSVersion int

	MonitoringSubnets []string

	Status    Status
	LastError string
	CreatedAt time.Time
	UpdatedAt time.Time
}

func (t *ResellerTunnel) Validate() error {
	if t.Name == "" {
		return ErrInvalidName
	}
	if t.VPNType != VPNTypeWireGuard && t.VPNType != VPNTypeL2TP {
		return ErrInvalidVPNType
	}
	return nil
}

func (t *ResellerTunnel) GenerateNamespace() {
	t.Namespace = fmt.Sprintf("ns-res-%d", t.ResellerID)
}

func (t *ResellerTunnel) IsActive() bool {
	return t.Status == StatusActive
}

func (t *ResellerTunnel) CanActivate() bool {
	return t.Status == StatusPending || t.Status == StatusDown || t.Status == StatusError
}

func (t *ResellerTunnel) CanDeactivate() bool {
	return t.Status == StatusActive || t.Status == StatusDown
}

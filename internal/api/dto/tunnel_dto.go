package dto

import (
	"time"

	"github.com/google/uuid"

	"github.com/jinom/vpn/internal/domain/tunnel"
)

type CreateTunnelRequest struct {
	ResellerID        int64    `json:"reseller_id" validate:"required"`
	CompanyID         int64    `json:"company_id" validate:"required"`
	Name              string   `json:"name" validate:"required,min=1,max=100"`
	VPNType           string   `json:"vpn_type" validate:"required,oneof=wireguard l2tp"`
	RouterIP          string   `json:"router_ip" validate:"required"`
	RouterUsername    string   `json:"router_username" validate:"required"`
	RouterPassword    string   `json:"router_password" validate:"required"`
	RouterOSVersion   int      `json:"routeros_version"`
	MonitoringSubnets []string `json:"monitoring_subnets"`
}

type TunnelResponse struct {
	ID              uuid.UUID `json:"id"`
	ResellerID      int64     `json:"reseller_id"`
	CompanyID       int64     `json:"company_id"`
	Name            string    `json:"name"`
	VPNType         string    `json:"vpn_type"`
	Namespace       string    `json:"namespace"`
	TunnelIndex     int       `json:"tunnel_index"`
	ServerPublicKey string    `json:"server_public_key,omitempty"`
	ServerListenPort int      `json:"server_listen_port,omitempty"`
	ServerIPAddress string    `json:"server_ip_address,omitempty"`
	ClientIPAddress string    `json:"client_ip_address,omitempty"`
	RouterIP        string    `json:"router_ip,omitempty"`
	RouterOSVersion int       `json:"routeros_version"`
	MonitoringSubnets []string `json:"monitoring_subnets"`
	Status          string    `json:"status"`
	LastError       string    `json:"last_error,omitempty"`
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`
}

type TunnelStatusResponse struct {
	ID            uuid.UUID `json:"id"`
	Status        string    `json:"status"`
	Namespace     string    `json:"namespace"`
	LastError     string    `json:"last_error,omitempty"`
	PeerReachable bool      `json:"peer_reachable"`
}

type ListResponse struct {
	Data  []TunnelResponse `json:"data"`
	Total int64            `json:"total"`
	Page  int              `json:"page"`
	Limit int              `json:"limit"`
}

func ToTunnelResponse(t *tunnel.ResellerTunnel) TunnelResponse {
	return TunnelResponse{
		ID:                t.ID,
		ResellerID:        t.ResellerID,
		CompanyID:         t.CompanyID,
		Name:              t.Name,
		VPNType:           string(t.VPNType),
		Namespace:         t.Namespace,
		TunnelIndex:       t.TunnelIndex,
		ServerPublicKey:   t.ServerPublicKey,
		ServerListenPort:  t.ServerListenPort,
		ServerIPAddress:   t.ServerIPAddress,
		ClientIPAddress:   t.ClientIPAddress,
		RouterIP:          t.RouterIP,
		RouterOSVersion:   t.RouterOSVersion,
		MonitoringSubnets: t.MonitoringSubnets,
		Status:            string(t.Status),
		LastError:         t.LastError,
		CreatedAt:         t.CreatedAt,
		UpdatedAt:         t.UpdatedAt,
	}
}

func ToTunnelListResponse(tunnels []tunnel.ResellerTunnel) []TunnelResponse {
	result := make([]TunnelResponse, len(tunnels))
	for i := range tunnels {
		result[i] = ToTunnelResponse(&tunnels[i])
	}
	return result
}

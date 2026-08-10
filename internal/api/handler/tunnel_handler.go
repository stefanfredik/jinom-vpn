package handler

import (
	"errors"
	"strconv"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/jinom/vpn/internal/api/dto"
	"github.com/jinom/vpn/internal/domain/tunnel"
	"github.com/jinom/vpn/internal/service"
)

type TunnelHandler struct {
	svc *service.TunnelService
	log *zap.Logger
}

func NewTunnelHandler(svc *service.TunnelService, log *zap.Logger) *TunnelHandler {
	return &TunnelHandler{svc: svc, log: log}
}

func (h *TunnelHandler) List(c *fiber.Ctx) error {
	page, _ := strconv.Atoi(c.Query("page", "1"))
	limit, _ := strconv.Atoi(c.Query("limit", "50"))

	filter := tunnel.Filter{Page: page, Limit: limit}

	if v := c.Query("company_id"); v != "" {
		id, _ := strconv.ParseInt(v, 10, 64)
		filter.CompanyID = &id
	}
	if v := c.Query("reseller_id"); v != "" {
		id, _ := strconv.ParseInt(v, 10, 64)
		filter.ResellerID = &id
	}
	if v := c.Query("status"); v != "" {
		s := tunnel.Status(v)
		filter.Status = &s
	}

	tunnels, total, err := h.svc.List(c.Context(), filter)
	if err != nil {
		return internalError(c, err)
	}

	return c.JSON(dto.ListResponse{
		Data:  dto.ToTunnelListResponse(tunnels),
		Total: total,
		Page:  page,
		Limit: limit,
	})
}

func (h *TunnelHandler) Create(c *fiber.Ctx) error {
	var req service.CreateTunnelRequest
	if err := c.BodyParser(&req); err != nil {
		return badRequest(c, "invalid request body")
	}

	if req.RouterOSVersion == 0 {
		req.RouterOSVersion = 7
	}

	t, err := h.svc.Create(c.Context(), req)
	if err != nil {
		if errors.Is(err, tunnel.ErrInvalidName) || errors.Is(err, tunnel.ErrInvalidVPNType) {
			return badRequest(c, err.Error())
		}
		return internalError(c, err)
	}

	return c.Status(fiber.StatusCreated).JSON(fiber.Map{
		"success": true,
		"data":    dto.ToTunnelResponse(t),
	})
}

func (h *TunnelHandler) Get(c *fiber.Ctx) error {
	id, err := uuid.Parse(c.Params("id"))
	if err != nil {
		return badRequest(c, "invalid tunnel id")
	}

	t, err := h.svc.GetByID(c.Context(), id)
	if err != nil {
		return handleTunnelError(c, err)
	}

	return c.JSON(fiber.Map{
		"success": true,
		"data":    dto.ToTunnelResponse(t),
	})
}

func (h *TunnelHandler) GetStatus(c *fiber.Ctx) error {
	id, err := uuid.Parse(c.Params("id"))
	if err != nil {
		return badRequest(c, "invalid tunnel id")
	}

	status, err := h.svc.GetStatus(c.Context(), id)
	if err != nil {
		return handleTunnelError(c, err)
	}

	return c.JSON(fiber.Map{
		"success": true,
		"data": dto.TunnelStatusResponse{
			ID:             status.ID,
			Status:         string(status.Status),
			Namespace:      status.Namespace,
			LastError:      status.LastError,
			PeerReachable:  status.PeerReachable,
			MikrotikStatus: status.MikrotikStatus,
			MikrotikIP:     status.MikrotikIP,
			MikrotikUptime: status.MikrotikUptime,
			Uptime:         status.Uptime,
		},
	})
}

func (h *TunnelHandler) GetScript(c *fiber.Ctx) error {
	id, err := uuid.Parse(c.Params("id"))
	if err != nil {
		return badRequest(c, "invalid tunnel id")
	}

	// Assuming the VPS public IP is passed via an environment variable or configuration.
	// We'll use the same VPS IP logic that Provision uses.
	// Since TunnelHandler doesn't have direct access to vpsPublicIP, we need it.
	// Ah wait, s.vpsPublicIP is inside TunnelService. TunnelService.GenerateRouterOSScript
	// should just get the vpsPublicIP from its own field!
	// Oh, I passed vpsPublicIP as an argument to GenerateRouterOSScript. Let me check if TunnelService has a getter or if I can just remove the argument. Let me check that. 
	// For now, I'll pass an empty string and we will see if we need to modify GenerateRouterOSScript. No, let's fix GenerateRouterOSScript to not need it!
	
	// Generate the script using the service which has access to vpsPublicIP internally
	script, err := h.svc.GenerateRouterOSScript(c.Context(), id)
	if err != nil {
		return handleTunnelError(c, err)
	}

	return c.JSON(fiber.Map{
		"success": true,
		"data": fiber.Map{
			"script": script,
		},
	})
}

func (h *TunnelHandler) Provision(c *fiber.Ctx) error {
	id, err := uuid.Parse(c.Params("id"))
	if err != nil {
		return badRequest(c, "invalid tunnel id")
	}

	if err := h.svc.Provision(c.Context(), id); err != nil {
		return handleTunnelError(c, err)
	}

	return c.JSON(fiber.Map{"success": true, "message": "tunnel provisioned to MikroTik"})
}

func (h *TunnelHandler) Activate(c *fiber.Ctx) error {
	id, err := uuid.Parse(c.Params("id"))
	if err != nil {
		return badRequest(c, "invalid tunnel id")
	}

	if err := h.svc.Activate(c.Context(), id); err != nil {
		if errors.Is(err, tunnel.ErrAlreadyActive) {
			return badRequest(c, err.Error())
		}
		return handleTunnelError(c, err)
	}

	return c.JSON(fiber.Map{"success": true, "message": "tunnel activated"})
}

func (h *TunnelHandler) Deactivate(c *fiber.Ctx) error {
	id, err := uuid.Parse(c.Params("id"))
	if err != nil {
		return badRequest(c, "invalid tunnel id")
	}

	if err := h.svc.Deactivate(c.Context(), id); err != nil {
		if errors.Is(err, tunnel.ErrNotActive) {
			return badRequest(c, err.Error())
		}
		return handleTunnelError(c, err)
	}

	return c.JSON(fiber.Map{"success": true, "message": "tunnel deactivated"})
}

func (h *TunnelHandler) Delete(c *fiber.Ctx) error {
	id, err := uuid.Parse(c.Params("id"))
	if err != nil {
		return badRequest(c, "invalid tunnel id")
	}

	if err := h.svc.Delete(c.Context(), id); err != nil {
		return handleTunnelError(c, err)
	}

	return c.JSON(fiber.Map{"success": true, "message": "tunnel deleted"})
}

func (h *TunnelHandler) GetMetrics(c *fiber.Ctx) error {
	id, err := uuid.Parse(c.Params("id"))
	if err != nil {
		return badRequest(c, "invalid tunnel id")
	}
	limit, _ := strconv.Atoi(c.Query("limit", "100"))

	metrics, err := h.svc.GetMetrics(c.Context(), id, limit)
	if err != nil {
		return internalError(c, err)
	}

	return c.JSON(fiber.Map{
		"success": true,
		"data":    metrics,
	})
}

func (h *TunnelHandler) GetHistory(c *fiber.Ctx) error {
	id, err := uuid.Parse(c.Params("id"))
	if err != nil {
		return badRequest(c, "invalid tunnel id")
	}
	limit, _ := strconv.Atoi(c.Query("limit", "50"))

	history, err := h.svc.GetStatusHistory(c.Context(), id, limit)
	if err != nil {
		return internalError(c, err)
	}

	return c.JSON(fiber.Map{
		"success": true,
		"data":    history,
	})
}

func handleTunnelError(c *fiber.Ctx, err error) error {
	if errors.Is(err, tunnel.ErrNotFound) {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
			"success": false,
			"error":   fiber.Map{"code": "NOT_FOUND", "message": "tunnel not found"},
		})
	}
	return internalError(c, err)
}

func badRequest(c *fiber.Ctx, message string) error {
	return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
		"success": false,
		"error":   fiber.Map{"code": "BAD_REQUEST", "message": message},
	})
}

func internalError(c *fiber.Ctx, err error) error {
	return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
		"success": false,
		"error":   fiber.Map{"code": "INTERNAL_ERROR", "message": err.Error()},
	})
}

func (h *TunnelHandler) SelectNOCReseller(c *fiber.Ctx) error {
	id, err := uuid.Parse(c.Params("id"))
	if err != nil {
		return badRequest(c, "invalid tunnel id")
	}

	var req struct {
		TechnicianIP string `json:"technician_ip"`
	}
	if len(c.Body()) > 0 {
		_ = c.BodyParser(&req)
	}

	if req.TechnicianIP == "" {
		req.TechnicianIP = c.IP()
	}

	if err := h.svc.SelectNOCReseller(c.Context(), req.TechnicianIP, id); err != nil {
		return internalError(c, err)
	}

	return c.JSON(fiber.Map{
		"success": true,
		"message": "NOC routing configured successfully",
		"mapped_ip": req.TechnicianIP,
	})
}

func (h *TunnelHandler) CreateNOCTechnician(c *fiber.Ctx) error {
	var req struct {
		Name string `json:"name"`
	}
	if err := c.BodyParser(&req); err != nil {
		return badRequest(c, "invalid request body")
	}

	if req.Name == "" {
		return badRequest(c, "technician name is required")
	}

	ip, config, err := h.svc.CreateNOCTechnician(c.Context(), req.Name)
	if err != nil {
		return internalError(c, err)
	}

	return c.JSON(fiber.Map{
		"success": true,
		"data": fiber.Map{
			"name":   req.Name,
			"ip":     ip,
			"config": config,
		},
	})
}

func (h *TunnelHandler) ListNOCTechnicians(c *fiber.Ctx) error {
	users, err := h.svc.ListNOCTechnicians(c.Context())
	if err != nil {
		return internalError(c, err)
	}
	return c.JSON(fiber.Map{
		"success": true,
		"data":    users,
	})
}

func (h *TunnelHandler) DeleteNOCTechnician(c *fiber.Ctx) error {
	var req struct {
		PublicKey string `json:"public_key"`
	}
	if err := c.BodyParser(&req); err != nil {
		return badRequest(c, "invalid request body")
	}
	if req.PublicKey == "" {
		return badRequest(c, "public_key is required")
	}

	if err := h.svc.DeleteNOCTechnician(c.Context(), req.PublicKey); err != nil {
		return internalError(c, err)
	}

	return c.JSON(fiber.Map{
		"success": true,
		"message": "NOC technician deleted successfully",
	})
}

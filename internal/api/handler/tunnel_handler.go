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
	page, err := strconv.Atoi(c.Query("page", "1"))
	if err != nil || page < 1 {
		page = 1
	}
	limit, err := strconv.Atoi(c.Query("limit", "50"))
	if err != nil || limit < 1 {
		limit = 50
	}
	if limit > 500 {
		limit = 500
	}

	filter := tunnel.Filter{Page: page, Limit: limit}

	if v := c.Query("company_id"); v != "" {
		id, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			return badRequest(c, "invalid company_id")
		}
		filter.CompanyID = &id
	}
	if v := c.Query("reseller_id"); v != "" {
		id, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			return badRequest(c, "invalid reseller_id")
		}
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

func (h *TunnelHandler) UpdateSubnets(c *fiber.Ctx) error {
	id, err := uuid.Parse(c.Params("id"))
	if err != nil {
		return badRequest(c, "invalid tunnel id")
	}

	var req service.UpdateSubnetsRequest
	if err := c.BodyParser(&req); err != nil {
		return badRequest(c, "invalid request body")
	}

	t, err := h.svc.UpdateSubnets(c.Context(), id, req)
	if err != nil {
		return handleTunnelError(c, err)
	}

	return c.JSON(fiber.Map{
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

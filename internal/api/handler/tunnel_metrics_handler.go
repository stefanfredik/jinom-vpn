package handler

import (
	"strconv"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"

	"github.com/jinom/vpn/internal/api/dto"
)

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
			ID:                status.ID,
			Status:            string(status.Status),
			Namespace:         status.Namespace,
			LastError:         status.LastError,
			PeerReachable:     status.PeerReachable,
			MikrotikStatus:    status.MikrotikStatus,
			MikrotikIP:        status.MikrotikIP,
			MikrotikUptime:    status.MikrotikUptime,
			Uptime:            status.Uptime,
			ConfiguredSubnets: status.ConfiguredSubnets,
			ActiveSubnets:     status.ActiveSubnets,
		},
	})
}

func (h *TunnelHandler) GetScript(c *fiber.Ctx) error {
	id, err := uuid.Parse(c.Params("id"))
	if err != nil {
		return badRequest(c, "invalid tunnel id")
	}

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

func (h *TunnelHandler) GetMetrics(c *fiber.Ctx) error {
	id, err := uuid.Parse(c.Params("id"))
	if err != nil {
		return badRequest(c, "invalid tunnel id")
	}
	limit, err := strconv.Atoi(c.Query("limit", "100"))
	if err != nil || limit < 1 {
		limit = 100
	}
	if limit > 1000 {
		limit = 1000
	}

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
	limit, err := strconv.Atoi(c.Query("limit", "50"))
	if err != nil || limit < 1 {
		limit = 50
	}
	if limit > 1000 {
		limit = 1000
	}

	history, err := h.svc.GetStatusHistory(c.Context(), id, limit)
	if err != nil {
		return internalError(c, err)
	}

	return c.JSON(fiber.Map{
		"success": true,
		"data":    history,
	})
}

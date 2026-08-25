package handler

import (
	"net"
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
)

func cleanIP(ipStr string) string {
	ipStr = strings.TrimSpace(ipStr)
	if strings.Contains(ipStr, ",") {
		ipStr = strings.TrimSpace(strings.Split(ipStr, ",")[0])
	}
	if host, _, err := net.SplitHostPort(ipStr); err == nil {
		ipStr = host
	}
	return strings.TrimSpace(ipStr)
}

func (h *TunnelHandler) GetNOCStatus(c *fiber.Ctx) error {
	var req struct {
		TechnicianIP string `json:"technician_ip"`
	}
	if len(c.Body()) > 0 {
		_ = c.BodyParser(&req)
	}

	if req.TechnicianIP == "" {
		req.TechnicianIP = c.Get("CF-Connecting-IP")
		if req.TechnicianIP == "" {
			req.TechnicianIP = c.Get("X-Real-IP")
		}
		if req.TechnicianIP == "" {
			req.TechnicianIP = c.Get("X-Forwarded-For")
		}
		if req.TechnicianIP == "" {
			req.TechnicianIP = c.IP()
		}
	}
	req.TechnicianIP = cleanIP(req.TechnicianIP)

	status, err := h.svc.GetNOCStatus(c.Context(), req.TechnicianIP)
	if err != nil {
		return internalError(c, err)
	}

	return c.JSON(fiber.Map{
		"success": true,
		"data":    status,
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
		req.TechnicianIP = c.Get("CF-Connecting-IP")
		if req.TechnicianIP == "" {
			req.TechnicianIP = c.Get("X-Real-IP")
		}
		if req.TechnicianIP == "" {
			req.TechnicianIP = c.Get("X-Forwarded-For")
		}
		if req.TechnicianIP == "" {
			req.TechnicianIP = c.IP()
		}
	}
	req.TechnicianIP = cleanIP(req.TechnicianIP)

	mappedIP, err := h.svc.SelectNOCReseller(c.Context(), req.TechnicianIP, id)
	if err != nil {
		return internalError(c, err)
	}

	return c.JSON(fiber.Map{
		"success":   true,
		"message":   "NOC routing configured successfully",
		"mapped_ip": mappedIP,
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

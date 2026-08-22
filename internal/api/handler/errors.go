package handler

import (
	"errors"

	"github.com/gofiber/fiber/v2"

	"github.com/jinom/vpn/internal/domain/tunnel"
)

func handleTunnelError(c *fiber.Ctx, err error) error {
	if errors.Is(err, tunnel.ErrNotFound) {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
			"success": false,
			"error":   fiber.Map{"code": "NOT_FOUND", "message": "tunnel not found"},
		})
	}
	if errors.Is(err, tunnel.ErrInvalidSubnet) {
		return badRequest(c, err.Error())
	}
	if errors.Is(err, tunnel.ErrConflict) {
		return c.Status(fiber.StatusConflict).JSON(fiber.Map{
			"success": false,
			"error": fiber.Map{
				"code":    "CONFLICT",
				"message": "Tunnel was modified by another request. Reload the page and try again.",
			},
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

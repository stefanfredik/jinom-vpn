package handler

import (
	"github.com/gofiber/fiber/v2"

	"github.com/jinom/vpn/internal/platform/database"
)

type HealthHandler struct {
	db *database.PostgresDB
}

func NewHealthHandler(db *database.PostgresDB) *HealthHandler {
	return &HealthHandler{db: db}
}

func (h *HealthHandler) Health(c *fiber.Ctx) error {
	if err := h.db.Ping(c.Context()); err != nil {
		return c.Status(fiber.StatusServiceUnavailable).JSON(fiber.Map{
			"status":   "unhealthy",
			"database": "disconnected",
		})
	}

	return c.JSON(fiber.Map{
		"status":   "healthy",
		"service":  "jinom-vpn",
		"database": "connected",
	})
}

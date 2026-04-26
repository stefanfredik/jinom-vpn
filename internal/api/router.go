package api

import (
	"github.com/gofiber/fiber/v2"

	"github.com/jinom/vpn/internal/api/handler"
	"github.com/jinom/vpn/internal/api/middleware"
)

type RouterDeps struct {
	TunnelHandler *handler.TunnelHandler
	HealthHandler *handler.HealthHandler
	APIKey        string
}

func RegisterRoutes(app *fiber.App, deps RouterDeps) {
	app.Get("/health", deps.HealthHandler.Health)

	api := app.Group("/api/v1", middleware.APIKeyAuth(deps.APIKey))

	tunnels := api.Group("/tunnels")
	tunnels.Get("/", deps.TunnelHandler.List)
	tunnels.Post("/", deps.TunnelHandler.Create)
	tunnels.Get("/:id", deps.TunnelHandler.Get)
	tunnels.Get("/:id/status", deps.TunnelHandler.GetStatus)
	tunnels.Post("/:id/provision", deps.TunnelHandler.Provision)
	tunnels.Post("/:id/activate", deps.TunnelHandler.Activate)
	tunnels.Post("/:id/deactivate", deps.TunnelHandler.Deactivate)
	tunnels.Delete("/:id", deps.TunnelHandler.Delete)
}

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

	// Serve Static Dashboard
	app.Static("/", "./web")

	api := app.Group("/api/v1", middleware.APIKeyAuth(deps.APIKey))
	api.Post("/noc/users", deps.TunnelHandler.CreateNOCTechnician)
	api.Get("/noc/users", deps.TunnelHandler.ListNOCTechnicians)
	api.Delete("/noc/users", deps.TunnelHandler.DeleteNOCTechnician)

	tunnels := api.Group("/tunnels")
	tunnels.Get("/", deps.TunnelHandler.List)
	tunnels.Post("/", deps.TunnelHandler.Create)
	tunnels.Get("/:id", deps.TunnelHandler.Get)
	tunnels.Get("/:id/status", deps.TunnelHandler.GetStatus)
	tunnels.Get("/:id/metrics", deps.TunnelHandler.GetMetrics)
	tunnels.Get("/:id/history", deps.TunnelHandler.GetHistory)
	tunnels.Post("/:id/provision", deps.TunnelHandler.Provision)
	tunnels.Post("/:id/activate", deps.TunnelHandler.Activate)
	tunnels.Post("/:id/deactivate", deps.TunnelHandler.Deactivate)
	tunnels.Post("/:id/noc/select", deps.TunnelHandler.SelectNOCReseller)
	tunnels.Delete("/:id", deps.TunnelHandler.Delete)
}

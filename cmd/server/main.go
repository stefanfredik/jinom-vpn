package main

import (
	"os"
	"os/signal"
	"syscall"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/recover"
	"go.uber.org/zap"

	"github.com/jinom/vpn/internal/api"
	"github.com/jinom/vpn/internal/api/handler"
	"github.com/jinom/vpn/internal/platform/config"
	"github.com/jinom/vpn/internal/platform/crypto"
	"github.com/jinom/vpn/internal/platform/database"
	"github.com/jinom/vpn/internal/platform/logger"
	"github.com/jinom/vpn/internal/repository/postgres"
	"github.com/jinom/vpn/internal/service"
)

func main() {
	cfg := config.LoadConfig(".env")

	zapLogger, err := logger.NewLogger(cfg.AppEnv)
	if err != nil {
		panic("failed to initialize logger: " + err.Error())
	}
	defer zapLogger.Sync()

	zapLogger.Info("Starting jinom-vpn",
		zap.String("env", cfg.AppEnv),
		zap.String("listen", cfg.ListenAddr),
	)

	db, err := database.NewPostgresDB(cfg, zapLogger)
	if err != nil {
		zapLogger.Fatal("Failed to connect to database", zap.Error(err))
	}
	defer db.Close()

	var cryptoSvc *crypto.Crypto
	if cfg.Security.MasterKey != "" {
		c, err := crypto.NewCrypto(cfg.Security.MasterKey)
		if err != nil {
			zapLogger.Error("Failed to initialize crypto", zap.Error(err))
		} else {
			cryptoSvc = c
			zapLogger.Info("Crypto service initialized")
		}
	} else {
		zapLogger.Warn("MASTER_KEY not set, credentials stored as plaintext")
	}

	tunnelRepo := postgres.NewTunnelRepository(db, cryptoSvc, zapLogger)

	nsSvc := service.NewNamespaceService(zapLogger)
	wgSvc := service.NewWireGuardService(nsSvc, zapLogger)
	l2tpSvc := service.NewL2TPService(nsSvc, zapLogger)
	provisionerSvc := service.NewProvisionerService(zapLogger)

	vpsPublicIP := cfg.VPSPublicIP
	if vpsPublicIP == "" {
		zapLogger.Warn("⚠️  VPS_PUBLIC_IP not configured in .env file! MikroTik provisioning will FAIL if attempted.")
		zapLogger.Warn("Update .env file: VPS_PUBLIC_IP=<your-public-ip>")
		vpsPublicIP = "0.0.0.0" // Will be validated at provision time
	} else {
		zapLogger.Info("VPS_PUBLIC_IP configured", zap.String("ip", vpsPublicIP))
	}

	tunnelSvc := service.NewTunnelService(
		tunnelRepo, nsSvc, wgSvc, l2tpSvc, provisionerSvc, vpsPublicIP, zapLogger,
	)

	healthMonitor := service.NewHealthMonitorService(tunnelRepo, nsSvc, zapLogger)
	healthMonitor.Start()
	defer healthMonitor.Stop()

	app := fiber.New(fiber.Config{
		ErrorHandler: func(c *fiber.Ctx, err error) error {
			code := fiber.StatusInternalServerError
			if e, ok := err.(*fiber.Error); ok {
				code = e.Code
			}
			return c.Status(code).JSON(fiber.Map{
				"success": false,
				"error": fiber.Map{
					"code":    code,
					"message": err.Error(),
				},
			})
		},
	})

	app.Use(recover.New())
	app.Use(cors.New(cors.Config{
		AllowOrigins: "*",
		AllowMethods: "GET,POST,PUT,DELETE,OPTIONS",
		AllowHeaders: "Origin, Content-Type, Accept, X-API-Key",
	}))

	tunnelHandler := handler.NewTunnelHandler(tunnelSvc, zapLogger)
	healthHandler := handler.NewHealthHandler(db)

	api.RegisterRoutes(app, api.RouterDeps{
		TunnelHandler: tunnelHandler,
		HealthHandler: healthHandler,
		APIKey:        cfg.Security.APIKey,
	})

	go func() {
		if err := app.Listen(cfg.ListenAddr); err != nil {
			zapLogger.Fatal("Server failed to start", zap.Error(err))
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	zapLogger.Info("Shutting down jinom-vpn...")
	_ = app.Shutdown()
}

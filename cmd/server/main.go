package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/recover"
	"go.uber.org/zap"

	"github.com/jinom/vpn/internal/api"
	"github.com/jinom/vpn/internal/api/handler"
	"github.com/jinom/vpn/internal/domain/tunnel"
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

	// RUN MIGRATION ONCE: Update all L2TP PSKs to the global one
	migCtx := context.Background()
	tuns, _, _ := tunnelRepo.FindAll(migCtx, tunnel.Filter{})
	for i := range tuns {
		tun := &tuns[i]
		if tun.VPNType == "l2tp" && tun.PSK != "JinomGlobalSecret2026!" {
			tun.PSK = "JinomGlobalSecret2026!"
			if err := tunnelRepo.Save(migCtx, tun); err != nil {
				zapLogger.Error("Failed to migrate PSK", zap.String("tunnel", tun.Name), zap.Error(err))
			} else {
				zapLogger.Info("Migrated L2TP PSK to Global Secret", zap.String("tunnel", tun.Name))
			}
		}
	}
	// END MIGRATION

	nsSvc := service.NewNamespaceService(zapLogger)
	wgSvc := service.NewWireGuardService(nsSvc, zapLogger)
	l2tpSvc := service.NewL2TPService(nsSvc, cfg.VPSPublicIP, zapLogger)
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

	tunnelSvc.Reconcile(context.Background())

	healthMonitor := service.NewHealthMonitorService(tunnelRepo, nsSvc, wgSvc, l2tpSvc, vpsPublicIP, zapLogger)
	// Hook agar Delete tunnel sekaligus melepaskan entry map in-memory di
	// monitor — jaga supaya `states` tidak tumbuh tak terbatas saat banyak
	// tunnel dibuat & dihapus.
	tunnelSvc.SetOnDeleteHook(healthMonitor.Forget)
	// Route automatic recovery through TunnelService so it runs under the same
	// setupMu as operator actions (activate/deactivate/delete), preventing a
	// health-triggered teardown+setup from racing a concurrent API call on the
	// same namespace/iptables/chap-secrets state.
	healthMonitor.SetRecoverHook(tunnelSvc.RecoverTunnel)
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

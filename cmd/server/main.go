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

	// Tolak berjalan tanpa root. Semua operasi runtime (ip netns, wg, iptables,
	// menulis /etc/ppp dan /etc/ipsec.*) butuh root; tanpa itu setiap
	// pemeriksaan "namespace ada?" gagal dengan "Operation not permitted" dan
	// Reconcile menandai SELURUH tunnel sebagai error di database bersama —
	// persis insiden 2026-09-17 14:46 UTC ketika binary dijalankan tanpa sudo
	// dari sesi lain sementara service systemd yang sah tetap berjalan.
	if os.Geteuid() != 0 {
		zapLogger.Fatal("jinom-vpn must run as root (ip netns / wireguard / iptables). " +
			"Use `sudo ./bin/jinom-vpn` or the systemd unit — refusing to start so the shared database is not poisoned.")
	}

	// FIX: Fail-fast if API_KEY is not configured. This prevents the server
	// from running with an empty API key, which would bypass all authentication.
	if cfg.Security.APIKey == "" {
		zapLogger.Fatal("API_KEY environment variable is required but not set. " +
			"Set it in your .env file or environment to enable authentication.")
	}

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

	// VPS_PUBLIC_IP harus sudah final SEBELUM L2TPService dibangun: konstruktornya
	// menulis /etc/ipsec.conf, dan "left=" kosong menghasilkan conn yang gagal
	// dimuat charon — yaitu seluruh L2TP mati. Sebelumnya nilai mentah cfg
	// dipakai di sini sementara fallback baru diterapkan beberapa baris di bawah.
	vpsPublicIP := cfg.VPSPublicIP
	if vpsPublicIP == "" {
		zapLogger.Warn("⚠️  VPS_PUBLIC_IP not configured in .env file! MikroTik provisioning will FAIL if attempted.")
		zapLogger.Warn("Update .env file: VPS_PUBLIC_IP=<your-public-ip>")
		vpsPublicIP = "0.0.0.0" // Will be validated at provision time
	} else {
		zapLogger.Info("VPS_PUBLIC_IP configured", zap.String("ip", vpsPublicIP))
	}

	nsSvc := service.NewNamespaceService(zapLogger)
	wgSvc := service.NewWireGuardService(nsSvc, zapLogger)
	l2tpSvc := service.NewL2TPService(nsSvc, vpsPublicIP, cfg.L2TPSNATMode, zapLogger)
	provisionerSvc := service.NewProvisionerService(zapLogger)

	// Synchronize global L2TP IPSec PSK to all tunnels in database
	if psk := l2tpSvc.GetPSK(); psk != "" {
		if err := tunnelRepo.SyncL2TPPSK(context.Background(), psk); err != nil {
			zapLogger.Warn("Failed to sync L2TP PSK for existing tunnels", zap.Error(err))
		} else {
			zapLogger.Info("Synchronized global L2TP PSK across all database tunnels", zap.Int("psk_len", len(psk)))
		}
	}

	// Pemeliharaan sekali jalan sebelum Reconcile:
	//   - menyusun ulang chap-secrets dari database, memulihkan entri yang
	//     terhapus oleh pencocokan namespace berawalan;
	//   - menyapu sisa rule DNAT/SNAT dari desain per-namespace lama, yang
	//     sebelumnya diulang pada setiap Setup dan Teardown.
	if tunnels, err := tunnelRepo.FindMonitored(context.Background()); err != nil {
		zapLogger.Warn("Startup maintenance skipped: failed to list tunnels", zap.Error(err))
	} else {
		if err := l2tpSvc.RebuildChapSecrets(tunnels); err != nil {
			zapLogger.Error("Failed to rebuild chap-secrets", zap.Error(err))
		}
		l2tpSvc.PurgeLegacyRouting(tunnels)
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

package main

import (
	"context"
	"fmt"
	"log"
    "os"

	"go.uber.org/zap"

	"github.com/jinom/vpn/internal/platform/config"
	"github.com/jinom/vpn/internal/platform/crypto"
	"github.com/jinom/vpn/internal/platform/database"
	"github.com/jinom/vpn/internal/domain/tunnel"
	"github.com/jinom/vpn/internal/repository/postgres"
	"github.com/jinom/vpn/pkg/mikrotik"
)

func main() {
    os.Setenv("DB_HOST", "127.0.0.1")
    os.Setenv("DB_PORT", "15432")
    os.Setenv("DB_USER", "nms_user")
    os.Setenv("DB_PASSWORD", "nms_pass")
    os.Setenv("DB_NAME", "nms_db")
    os.Setenv("DB_SSL_MODE", "disable")
    os.Setenv("MASTER_KEY", "Ik6S/fT5PMKOU7cH+Q8ql04BEpoETEazz58RUb6iN2A=")

	cfg := config.LoadConfig("")

	logger, _ := zap.NewDevelopment()
	db, err := database.NewPostgresDB(cfg, logger)
	if err != nil {
		log.Fatalf("failed to connect db: %v", err)
	}

	var cryptoSvc *crypto.Crypto
	if cfg.Security.MasterKey != "" {
		cryptoSvc, _ = crypto.NewCrypto(cfg.Security.MasterKey)
	}

	repo := postgres.NewTunnelRepository(db, cryptoSvc, logger)
	tunnels, _, err := repo.FindAll(context.Background(), tunnel.Filter{})
	if err != nil {
		log.Fatalf("failed to list tunnels: %v", err)
	}

	for _, t := range tunnels {
		if t.RouterIP == "10.70.94.190" {
			fmt.Printf("Testing router: %s, username: %s\n", t.RouterIP, t.RouterUsername)
			client, err := mikrotik.NewClient(t.RouterIP, t.RouterUsername, t.RouterPassword, t.RouterOSVersion >= 7)
			if err != nil {
				fmt.Printf("Failed to connect: %v\n", err)
				continue
			}

			fmt.Printf("Testing /log/print...\n")
			resLog, _ := client.Run("/log/print", nil)
			for i, r := range resLog {
				if len(resLog)-i <= 10 { // print last 10 logs
					fmt.Printf("Log: %s - %s\n", r["topics"], r["message"])
				}
			}

            client.Close()
		}
	}
}

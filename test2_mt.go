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

			fmt.Printf("Testing /interface/l2tp-client/add...\n")
			err = client.RunCommand(mikrotik.Command{
				Path: "/interface/l2tp-client/add",
				Params: map[string]string{
					"name":         "l2tp-jinom",
					"connect-to":   "10.70.103.56",
					"user":         "jinom-res-123",
					"password":     "BpKoC95iOB3OYw5PA1bWeeip",
					"use-ipsec":    "yes",
					"ipsec-secret": "tTNWtHoC9mMCeghgIa8xYl6QUzqS10Ow",
					"disabled":     "no",
				},
			})
			fmt.Printf("Add Interface Result: %v\n", err)

			fmt.Printf("Testing /ip/route/add...\n")
			err = client.RunCommand(mikrotik.Command{
				Path: "/ip/route/add",
				Params: map[string]string{
					"dst-address": "10.250.0.0/16",
					"gateway":     "l2tp-jinom",
					"comment":     "jinom-nms",
				},
			})
			fmt.Printf("Add Route Result: %v\n", err)

            client.Close()
		}
	}
}

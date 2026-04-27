package main

import (
	"context"
	"fmt"
	"log"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/jinom/vpn/internal/platform/config"
	"github.com/jinom/vpn/internal/platform/crypto"
	"github.com/jinom/vpn/internal/platform/database"
	"github.com/jinom/vpn/internal/repository/postgres"
)

func main() {
	cfg := config.LoadConfig("")
    cfg.Database.Host = "127.0.0.1"
    cfg.Database.Port = 15432
    cfg.Database.User = "nms_user"
    cfg.Database.Password = "nms_pass"
    cfg.Database.Name = "nms_db"
    cfg.Security.MasterKey = "Ik6S/fT5PMKOU7cH+Q8ql04BEpoETEazz58RUb6iN2A="

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
	id, _ := uuid.Parse("c907c0f0-3685-46e3-8d69-fd60c19a34b5")
	t, err := repo.FindByID(context.Background(), id)
	if err != nil {
		log.Fatalf("failed to find tunnel: %v", err)
	}

	fmt.Printf("Username: %s\n", t.L2TPUsername)
	fmt.Printf("Password: %s\n", t.L2TPPassword)
	fmt.Printf("PSK: %s\n", t.PSK)
}

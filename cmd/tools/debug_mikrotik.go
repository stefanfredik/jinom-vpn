package main

import (
	"context"
	"fmt"
	"log"

	"github.com/go-routeros/routeros/v3"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/jinom/vpn/internal/platform/config"
	"github.com/jinom/vpn/internal/platform/crypto"
	"github.com/jinom/vpn/internal/platform/database"
	"github.com/jinom/vpn/internal/repository/postgres"
)

func main() {
	cfg := config.LoadConfig(".env")
	zapLogger, _ := zap.NewDevelopment()

	db, err := database.NewPostgresDB(cfg, zapLogger)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	var cryptoSvc *crypto.Crypto
	if cfg.Security.MasterKey != "" {
		c, err := crypto.NewCrypto(cfg.Security.MasterKey)
		if err != nil {
			log.Fatal(err)
		}
		cryptoSvc = c
	}

	repo := postgres.NewTunnelRepository(db, cryptoSvc, zapLogger)

	ctx := context.Background()
	tunnelID, err := uuid.Parse("92f4b875-3102-47a4-bb93-fe4c25322f6b") // PT. AKSES INTERNET RAKYAT
	if err != nil {
		log.Fatal(err)
	}

	t, err := repo.FindByID(ctx, tunnelID)
	if err != nil {
		log.Fatal("Error finding tunnel:", err)
	}

	addr := fmt.Sprintf("%s:%d", t.RouterIP, t.RouterAPIPort)
	fmt.Printf("Connecting to MikroTik %s as %s...\n", addr, t.RouterUsername)

	conn, err := routeros.DialContext(ctx, addr, t.RouterUsername, t.RouterPassword)
	if err != nil {
		log.Fatal("Dial failed:", err)
	}
	defer conn.Close()

	// runAndPrint(conn, "/interface/l2tp-client/print")
	// runAndPrint(conn, "/ip/ipsec/peer/print")
	// runAndPrint(conn, "/ip/ipsec/active-peers/print")
	runAndPrint(conn, "/ip/firewall/filter/print")
	runAndPrint(conn, "/ip/firewall/nat/print")
	// runAndPrint(conn, "/log/print")
}

func runAndPrint(conn *routeros.Client, cmd string) {
	fmt.Printf("\n=== %s ===\n", cmd)
	res, err := conn.Run(cmd)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	for _, re := range res.Re {
		fmt.Printf("%+v\n", re.Map)
	}
}

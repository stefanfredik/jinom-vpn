package main

import (
	"context"
	"fmt"
	"log"

	"github.com/subosito/gotenv"
	"go.uber.org/zap"

	"github.com/jinom/vpn/internal/config"
	"github.com/jinom/vpn/internal/repository"
)

func main() {
	gotenv.Load(".env")
	cfg, err := config.Load()
	if err != nil { log.Fatal(err) }

	logger, _ := zap.NewDevelopment()
	repo, err := repository.NewPostgresTunnelRepository(cfg.Database, cfg.Security, logger)
	if err != nil { log.Fatal(err) }

	ctx := context.Background()
	tunnels, err := repo.List(ctx)
	if err != nil { log.Fatal(err) }

	count := 0
	for _, t := range tunnels {
		if t.VPNType == "L2TP" {
			t.PSK = "JinomGlobalSecret2026!"
			if err := repo.Save(ctx, t); err != nil {
				log.Printf("Failed saving %s: %v", t.Name, err)
			} else {
				count++
			}
		}
	}
	fmt.Printf("Berhasil mengupdate PSK L2TP untuk %d tunnel.\n", count)
}

package main

import (
	"log"
	"os"

	"github.com/kapralovs/passman/internal/app"
	"github.com/kapralovs/passman/internal/config"
	"github.com/kapralovs/passman/internal/crypto"
	"github.com/kapralovs/passman/internal/repository"
)

func main() {
	configPath := "config.json"
	sessionPath := "session.json"

	cfg, err := config.Load(configPath)
	if err != nil {
		log.Fatal("config not found. Run 'passman init' first.")
	}

	cryptoSvc, err := crypto.NewAESCrypto(cfg.Key)
	if err != nil {
		log.Fatal("invalid config key:", err)
	}

	vaultRepo := repository.NewVaultRepository()
	sessionRepo := repository.NewSessionRepository(sessionPath)

	app := app.New(configPath, cfg, vaultRepo, sessionRepo, cryptoSvc)

	if err := app.Run(os.Args[1:]); err != nil {
		log.Fatal(err)
	}
}
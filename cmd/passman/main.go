package main

import (
	"log"
	"os"

	"github.com/kapralovs/passman/internal/app"
	"github.com/kapralovs/passman/internal/crypto"
	"github.com/kapralovs/passman/internal/repository"
)

func main() {
	cfgRepo := repository.NewConfigRepository("config.json")
	vaultRepo := repository.NewVaultRepository()

	cfg, err := cfgRepo.Read()
	if err != nil {
		log.Fatal("config not found. Run 'passman init' first.")
	}

	cryptoSvc, err := crypto.NewAESCrypto(cfg.Key)
	if err != nil {
		log.Fatal("invalid config key:", err)
	}

	app := app.New(cfgRepo, vaultRepo, cryptoSvc)

	if err := app.Run(os.Args[1:]); err != nil {
		log.Fatal(err)
	}
}

package main

import (
	"log"
	"os"

	"github.com/kapralovs/passman/internal/app"
	"github.com/kapralovs/passman/internal/config"
)

func main() {
	configPath := "config.json"
	sessionPath := "session.json"

	cfg, err := config.Load(configPath)
	if err != nil {
		log.Fatal("config not found. Run 'passman init' first.")
	}

	app, err := app.New(configPath, cfg, sessionPath)
	if err != nil {
		log.Fatal(err)
	}

	if err = app.Run(os.Args[1:]); err != nil {
		log.Fatal(err)
	}
}

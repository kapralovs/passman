package commands

import (
	"fmt"
	"time"

	"github.com/kapralovs/passman/internal/models"
)

type InitCommand struct {
	*Context
}

func (c *InitCommand) Name() string {
	return "init"
}

func (c *InitCommand) Execute(args []string) error {
	key, err := c.Crypto.GenerateKey()
	if err != nil {
		return err
	}

	cfg := &models.Config{
		Key:             key,
		SessionDuration: time.Second * 30,
	}

	if err := c.Storage.SaveConfig(cfg); err != nil {
		return err
	}

	fmt.Println("Configuration initialized successfully")
	return nil
}

package commands

import (
	"flag"
	"fmt"
	"syscall"
	"time"

	"github.com/kapralovs/passman/internal/models"
	"golang.org/x/term"
)

type SignupCommand struct {
	*Context
}

func (c *SignupCommand) Name() string {
	return "signup"
}

func (c *SignupCommand) Execute(args []string) error {
	flagSet := flag.NewFlagSet(c.Name(), flag.ExitOnError)
	username := parseStringFlag(flagSet, "username", "Auth username")
	flagSet.Parse(args)

	if getFlagValue(username) == "" {
		return fmt.Errorf("username is required")
	}

	if c.Storage.UserExists(getFlagValue(username)) {
		return fmt.Errorf("user %s already exists", getFlagValue(username))
	}

	fmt.Print("Enter master password: ")
	password, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Println()
	if err != nil {
		return err
	}

	fmt.Print("Confirm master password: ")
	confirm, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Println()
	if err != nil {
		return err
	}

	if string(password) != string(confirm) {
		return fmt.Errorf("passwords do not match")
	}

	hashedPassword := c.Crypto.HashPassword(password)

	userData := &models.UserData{
		Credentials: models.Credentials{
			Username:    getFlagValue(username),
			Password:    hashedPassword,
			LastLoginAt: time.Now(),
		},
		Passwords: []models.PasswordEntry{},
	}

	if err := c.Storage.SaveUserData(getFlagValue(username), userData); err != nil {
		return err
	}

	// Update config with current user
	c.Config.Get().User.Name = getFlagValue(username)
	if err := c.Storage.SaveConfig(c.Config.Get()); err != nil {
		return err
	}

	fmt.Printf("User %s created successfully\n", getFlagValue(username))
	return nil
}

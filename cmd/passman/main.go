package main

import (
	"fmt"
	"log"
	"os"

	"github.com/kapralovs/passman/internal/commands"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	ctx, err := commands.NewContext()
	if err != nil {
		log.Fatalf("Failed to initialize: %v", err)
	}

	commands := map[string]commands.Command{
		"init":   &commands.InitCommand{Context: ctx},
		"signup": &commands.SignupCommand{Context: ctx},
		"login":  &commands.LoginCommand{Context: ctx},
		"add":    &commands.AddCommand{Context: ctx},
		"get":    &commands.GetCommand{Context: ctx},
	}

	cmd, exists := commands[os.Args[1]]
	if !exists {
		fmt.Printf("Unknown command: %s\n", os.Args[1])
		printUsage()
		os.Exit(1)
	}

	if err := cmd.Execute(os.Args[2:]); err != nil {
		log.Fatalf("Command failed: %v", err)
	}
}

func printUsage() {
	fmt.Println(`Password Manager Usage:
  init                    - Initialize password manager
  signup -username <name> - Create new user
  login [-username <name>]- Login to existing user
  add -service <name> -login <login> -password <pass> - Add new password
  get -service <name>     - Get password for service`)
}

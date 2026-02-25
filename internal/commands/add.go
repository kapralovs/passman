// internal/commands/add.go
package commands

import (
	"encoding/hex"
	"flag"
	"fmt"

	"github.com/kapralovs/passman/internal/models"
)

type AddCommand struct {
	*Context
}

func (c *AddCommand) Name() string {
	return "add"
}

func (c *AddCommand) Execute(args []string) error {
	// Проверяем, залогинен ли пользователь
	username, err := c.Config.GetCurrentUser()
	if err != nil {
		return fmt.Errorf("not logged in. Please run 'login' first")
	}

	// Парсим флаги
	flagSet := flag.NewFlagSet(c.Name(), flag.ExitOnError)
	service := parseStringFlag(flagSet, "service", "Service name")
	login := parseStringFlag(flagSet, "login", "Service login")
	password := parseStringFlag(flagSet, "password", "Service password")
	url := parseStringFlag(flagSet, "url", "Service URL (optional)")
	description := parseStringFlag(flagSet, "description", "Description (optional)")

	flagSet.Parse(args)

	// Валидация обязательных полей
	if getFlagValue(service) == "" {
		return fmt.Errorf("service name is required (use -service flag)")
	}
	if getFlagValue(login) == "" {
		return fmt.Errorf("login is required (use -login flag)")
	}
	if getFlagValue(password) == "" {
		return fmt.Errorf("password is required (use -password flag)")
	}

	// Загружаем данные пользователя
	userData, err := c.Storage.LoadUserData(username)
	if err != nil {
		return fmt.Errorf("failed to load user data: %w", err)
	}

	// Проверяем сессию
	if err := c.Session.Check(c.Config.Get(), userData.Credentials); err != nil {
		return fmt.Errorf("session expired: %w", err)
	}

	// Проверяем, не существует ли уже такой сервис
	for _, p := range userData.Passwords {
		if getFlagValue(service) == p.Service {
			return fmt.Errorf("service '%s' already exists", getFlagValue(service))
		}
	}

	key, err := c.Config.GetEncryptionKey()
	if err != nil {
		return fmt.Errorf("failed to get encryption key: %w", err)
	}

	// Шифруем пароль
	encrypted, err := c.Crypto.Encrypt(key, []byte(getFlagValue(password)))
	if err != nil {
		return fmt.Errorf("failed to encrypt password: %w", err)
	}

	// Создаем запись
	entry := models.PasswordEntry{
		Service:     getFlagValue(service),
		Login:       getFlagValue(login),
		Password:    hex.EncodeToString(encrypted),
		URL:         getFlagValue(url),
		Description: getFlagValue(description),
	}

	// Добавляем в массив
	userData.Passwords = append(userData.Passwords, entry)

	// Сохраняем обновленные данные
	if err := c.Storage.SaveUserData(username, userData); err != nil {
		return fmt.Errorf("failed to save user data: %w", err)
	}

	fmt.Printf("✓ Password for '%s' added successfully\n", getFlagValue(service))
	return nil
}

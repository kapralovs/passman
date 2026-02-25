// internal/commands/get.go
package commands

import (
	"encoding/hex"
	"flag"
	"fmt"
	"strings"

	"github.com/kapralovs/passman/internal/models"
)

type GetCommand struct {
	*Context
}

func (c *GetCommand) Name() string {
	return "get"
}

func (c *GetCommand) Execute(args []string) error {
	// Проверяем, залогинен ли пользователь
	username, err := c.Config.GetCurrentUser()
	if err != nil {
		return fmt.Errorf("not logged in. Please run 'login' first")
	}

	// Парсим флаги
	flagSet := flag.NewFlagSet(c.Name(), flag.ExitOnError)
	service := parseStringFlag(flagSet, "service", "Service name")
	showAll := flagSet.Bool("all", false, "Show all passwords")
	showPasswords := flagSet.Bool("show", false, "Show passwords in output (be careful!)")

	flagSet.Parse(args)

	// Проверяем, что указан сервис или флаг -all
	if !*showAll && getFlagValue(service) == "" {
		return fmt.Errorf("service name is required (use -service flag or -all to show all)")
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

	// Получаем ключ шифрования
	key, err := c.Config.GetEncryptionKey()
	if err != nil {
		return fmt.Errorf("failed to get encryption key: %w", err)
	}

	// Если запрошены все пароли
	if *showAll {
		return c.showAllPasswords(userData, key, *showPasswords)
	}

	// Ищем конкретный сервис
	return c.showSpecificPassword(userData, key, getFlagValue(service), *showPasswords)
}

func (c *GetCommand) showAllPasswords(userData *models.UserData, key string, showPasswords bool) error {
	if len(userData.Passwords) == 0 {
		fmt.Println("No passwords stored")
		return nil
	}

	fmt.Printf("\n🔐 Passwords for %s:\n", userData.Credentials.Username)
	fmt.Println(strings.Repeat("─", 60))

	for i, entry := range userData.Passwords {
		// Декодируем и расшифровываем пароль
		encrypted, err := hex.DecodeString(entry.Password)
		if err != nil {
			fmt.Printf("[%d] %s - ERROR: failed to decode password\n", i+1, entry.Service)
			continue
		}

		decrypted, err := c.Crypto.Decrypt(key, encrypted)
		if err != nil {
			fmt.Printf("[%d] %s - ERROR: failed to decrypt password\n", i+1, entry.Service)
			continue
		}

		// Выводим информацию
		fmt.Printf("[%d] 📁 %s\n", i+1, entry.Service)
		fmt.Printf("    👤 Login: %s\n", entry.Login)

		if showPasswords {
			fmt.Printf("    🔑 Password: %s\n", string(decrypted))
		} else {
			fmt.Printf("    🔑 Password: %s\n", maskPassword(string(decrypted)))
		}

		if entry.URL != "" {
			fmt.Printf("    🌐 URL: %s\n", entry.URL)
		}
		if entry.Description != "" {
			fmt.Printf("    📝 Description: %s\n", entry.Description)
		}
		fmt.Println()
	}

	if !showPasswords {
		fmt.Println("(Passwords are masked. Use -show flag to reveal them)")
	}

	return nil
}

func (c *GetCommand) showSpecificPassword(userData *models.UserData, key string, targetService string, showPasswords bool) error {
	for _, entry := range userData.Passwords {
		if targetService == entry.Service {
			// Декодируем и расшифровываем пароль
			encrypted, err := hex.DecodeString(entry.Password)
			if err != nil {
				return fmt.Errorf("failed to decode password: %w", err)
			}

			decrypted, err := c.Crypto.Decrypt(key, encrypted)
			if err != nil {
				return fmt.Errorf("failed to decrypt password: %w", err)
			}

			// Выводим пароль
			if showPasswords {
				fmt.Printf("%s", string(decrypted))
			} else {
				// Для одного сервиса показываем детальную информацию
				fmt.Printf("\n📁 %s\n", entry.Service)
				fmt.Printf("  👤 Login: %s\n", entry.Login)
				fmt.Printf("  🔑 Password: %s\n", string(decrypted))
				if entry.URL != "" {
					fmt.Printf("  🌐 URL: %s\n", entry.URL)
				}
				if entry.Description != "" {
					fmt.Printf("  📝 Description: %s\n", entry.Description)
				}
			}

			return nil
		}
	}

	return fmt.Errorf("service '%s' not found", targetService)
}

// Вспомогательная функция для маскировки пароля
func maskPassword(pwd string) string {
	if len(pwd) <= 4 {
		return strings.Repeat("*", len(pwd))
	}
	return pwd[:2] + strings.Repeat("*", len(pwd)-4) + pwd[len(pwd)-2:]
}

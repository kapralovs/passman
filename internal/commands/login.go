package commands

import (
	"flag"
	"fmt"
	"syscall"

	"golang.org/x/term"
)

type LoginCommand struct {
	*Context
}

func (c *LoginCommand) Name() string {
	return "login"
}

func (c *LoginCommand) Execute(args []string) error {
	// Парсим флаги
	flagSet := flag.NewFlagSet(c.Name(), flag.ExitOnError)
	username := parseStringFlag(flagSet, "username", "Auth username")
	flagSet.Parse(args)

	// Определяем целевого пользователя
	targetUser := getFlagValue(username)
	if targetUser == "" {
		// Пробуем получить текущего пользователя из конфига
		currentUser, err := c.Config.GetCurrentUser()
		if err != nil {
			return fmt.Errorf("no username specified and no current user. Use -username flag")
		}
		targetUser = currentUser
		fmt.Printf("Logging in as current user: %s\n", targetUser)
	}

	// Проверяем существование пользователя
	if !c.Storage.UserExists(targetUser) {
		return fmt.Errorf("user '%s' does not exist", targetUser)
	}

	// Запрашиваем пароль
	fmt.Printf("Enter master password for %s: ", targetUser)
	password, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Println()
	if err != nil {
		return fmt.Errorf("failed to read password: %w", err)
	}

	// Загружаем данные пользователя
	userData, err := c.Storage.LoadUserData(targetUser)
	if err != nil {
		return fmt.Errorf("failed to load user data: %w", err)
	}

	// Проверяем пароль
	hashedPassword := c.Crypto.HashPassword(password)
	if hashedPassword != userData.Credentials.Password {
		return fmt.Errorf("invalid password")
	}

	// Обновляем время последнего входа (сессия)
	c.Session.Update(&userData.Credentials)

	// Сохраняем обновленные данные пользователя
	if err := c.Storage.SaveUserData(targetUser, userData); err != nil {
		return fmt.Errorf("failed to save user data: %w", err)
	}

	// Обновляем конфиг с текущим пользователем
	if err := c.Config.UpdateUser(targetUser); err != nil {
		return fmt.Errorf("failed to update config: %w", err)
	}

	// ✅ ИСПРАВЛЕНО: используем геттер для получения длительности сессии
	sessionDuration := c.Config.GetSessionDuration()

	fmt.Printf("✓ Successfully logged in as '%s'\n", targetUser)
	fmt.Printf("  Session expires in %v\n", sessionDuration)

	return nil
}

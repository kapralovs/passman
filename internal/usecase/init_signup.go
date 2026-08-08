package usecase

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"time"

	"github.com/kapralovs/passman/internal/config"
	"github.com/kapralovs/passman/internal/entities"
	"github.com/kapralovs/passman/internal/repository"
	"golang.org/x/term"
)

// InitUsecase отвечает за инициализацию приложения.
type InitUsecase struct {
	ConfigPath string
}

// NewInitUsecase создаёт новый use case инициализации.
func NewInitUsecase(configPath string) *InitUsecase {
	return &InitUsecase{ConfigPath: configPath}
}

// Execute генерирует ключ и сохраняет конфигурацию.
func (u *InitUsecase) Execute() error {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}

	cfg := &config.Config{
		Key:             hex.EncodeToString(key),
		SessionDuration: 30,
	}

	return config.Save(u.ConfigPath, cfg)
}

// SignUpUsecase отвечает за регистрацию нового пользователя.
type SignUpUsecase struct {
	VaultRepo repository.VaultRepository
}

// NewSignUpUsecase создаёт новый use case регистрации.
func NewSignUpUsecase(vaultRepo repository.VaultRepository) *SignUpUsecase {
	return &SignUpUsecase{
		VaultRepo: vaultRepo,
	}
}

// Execute регистрирует нового пользователя. Возвращает обновлённый конфиг.
func (u *SignUpUsecase) Execute(cfg *config.Config, username string) (*config.Config, error) {
	fmt.Print("Password: ")
	password, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()
	if err != nil {
		return nil, err
	}

	hashedPassword := sha256.Sum256(password)

	// Проверяем, не занят ли username
	if _, err := u.VaultRepo.Read(username); err == nil {
		return nil, fmt.Errorf("user %q already exists", username)
	}

	ud := &entities.UserData{
		Credentials: entities.Credentials{
			Username:    username,
			Password:    hex.EncodeToString(hashedPassword[:]),
			LastLoginAt: time.Now(),
		},
		Passwords: []entities.PasswordEntry{},
	}

	cfg.User.Name = username
	if err := u.VaultRepo.Write(username, ud); err != nil {
		return nil, err
	}

	return cfg, nil
}

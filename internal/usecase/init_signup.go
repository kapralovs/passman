package usecase

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"time"

	"github.com/kapralovs/passman/internal/entities"
	"github.com/kapralovs/passman/internal/repository"
	"golang.org/x/term"
)

// InitUsecase отвечает за инициализацию приложения.
type InitUsecase struct {
	ConfigRepo repository.ConfigRepository
}

// NewInitUsecase создаёт новый use case инициализации.
func NewInitUsecase(cfgRepo repository.ConfigRepository) *InitUsecase {
	return &InitUsecase{ConfigRepo: cfgRepo}
}

// Execute генерирует ключ и сохраняет конфигурацию.
func (u *InitUsecase) Execute() error {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}

	cfg := &entities.Config{
		Key:             hex.EncodeToString(key),
		SessionDuration: 30,
	}

	return u.ConfigRepo.Write(cfg)
}

// SignUpUsecase отвечает за регистрацию нового пользователя.
type SignUpUsecase struct {
	ConfigRepo repository.ConfigRepository
	VaultRepo  repository.VaultRepository
}

// NewSignUpUsecase создаёт новый use case регистрации.
func NewSignUpUsecase(cfgRepo repository.ConfigRepository, vaultRepo repository.VaultRepository) *SignUpUsecase {
	return &SignUpUsecase{
		ConfigRepo: cfgRepo,
		VaultRepo:  vaultRepo,
	}
}

// Execute регистрирует нового пользователя.
func (u *SignUpUsecase) Execute(username string) error {
	fmt.Print("Password: ")
	password, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()
	if err != nil {
		return err
	}

	hashedPassword := sha256.Sum256(password)

	// Проверяем, не занят ли username
	if _, err := u.VaultRepo.Read(username); err == nil {
		return fmt.Errorf("user %q already exists", username)
	}

	ud := &entities.UserData{
		Credentials: entities.Credentials{
			Username:    username,
			Password:    hex.EncodeToString(hashedPassword[:]),
			LastLoginAt: time.Now(),
		},
		Passwords: []entities.PasswordEntry{},
	}

	cfg, err := u.ConfigRepo.Read()
	if err != nil {
		return err
	}

	cfg.User.Name = username
	if err := u.ConfigRepo.Write(cfg); err != nil {
		return err
	}

	return u.VaultRepo.Write(username, ud)
}

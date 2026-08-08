package usecase

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"

	"github.com/kapralovs/passman/internal/config"
	"github.com/kapralovs/passman/internal/entities"
	"github.com/kapralovs/passman/internal/repository"
	"github.com/kapralovs/passman/internal/session"
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
	if _, err := rand.Read(key); err != nil {
		return err
	}

	cfg := &config.Config{
		SessionDuration: 30,
		Key:             hex.EncodeToString(key),
	}

	return config.Save(u.ConfigPath, cfg)
}

// SignUpUsecase отвечает за регистрацию нового пользователя.
type SignUpUsecase struct {
	VaultRepo    repository.VaultRepository
	SessionRepo  repository.SessionRepository
}

// NewSignUpUsecase создаёт новый use case регистрации.
func NewSignUpUsecase(vaultRepo repository.VaultRepository, sessionRepo repository.SessionRepository) *SignUpUsecase {
	return &SignUpUsecase{
		VaultRepo:   vaultRepo,
		SessionRepo: sessionRepo,
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
			Username: username,
			Password: hex.EncodeToString(hashedPassword[:]),
		},
		Passwords: []entities.PasswordEntry{},
	}

	if err := u.VaultRepo.Write(username, ud); err != nil {
		return err
	}

	sess := &session.Session{
		Username: username,
		Trusted:  true,
	}

	return u.SessionRepo.Save(sess)
}

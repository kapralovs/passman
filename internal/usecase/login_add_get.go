package usecase

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/kapralovs/passman/internal/entities"
	"github.com/kapralovs/passman/internal/repository"
	"golang.org/x/term"
)

// LoginUsecase отвечает за вход в систему.
type LoginUsecase struct {
	ConfigRepo repository.ConfigRepository
	VaultRepo  repository.VaultRepository
}

// NewLoginUsecase создаёт новый use case входа.
func NewLoginUsecase(cfgRepo repository.ConfigRepository, vaultRepo repository.VaultRepository) *LoginUsecase {
	return &LoginUsecase{
		ConfigRepo: cfgRepo,
		VaultRepo:  vaultRepo,
	}
}

// Execute выполняет вход пользователя.
func (u *LoginUsecase) Execute() error {
	fmt.Print("Password: ")
	password, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()
	if err != nil {
		return err
	}

	hashedPassword := sha256.Sum256(password)

	cfg, err := u.ConfigRepo.Read()
	if err != nil {
		return err
	}

	userData, err := u.VaultRepo.Read(cfg.User.Name)
	if err != nil {
		return err
	}

	if hex.EncodeToString(hashedPassword[:]) != userData.Credentials.Password {
		return errors.New("wrong master password for user")
	}

	userData.Credentials.LastLoginAt = time.Now()
	return u.VaultRepo.Write(cfg.User.Name, userData)
}

// AddPasswordUsecase отвечает за добавление пароля.
type AddPasswordUsecase struct {
	ConfigRepo  repository.ConfigRepository
	VaultRepo   repository.VaultRepository
	Crypto      CryptoUsecase
	SessionTTL  time.Duration
}

// NewAddPasswordUsecase создаёт новый use case добавления пароля.
func NewAddPasswordUsecase(cfgRepo repository.ConfigRepository, vaultRepo repository.VaultRepository, crypto CryptoUsecase, sessionTTL time.Duration) *AddPasswordUsecase {
	return &AddPasswordUsecase{
		ConfigRepo: cfgRepo,
		VaultRepo:  vaultRepo,
		Crypto:     crypto,
		SessionTTL: sessionTTL,
	}
}

// Execute добавляет новый пароль.
func (u *AddPasswordUsecase) Execute(service, login, password string) error {
	cfg, err := u.ConfigRepo.Read()
	if err != nil {
		return err
	}

	userData, err := u.VaultRepo.Read(cfg.User.Name)
	if err != nil {
		return err
	}

	if time.Since(userData.Credentials.LastLoginAt) > u.SessionTTL {
		return errors.New("session exceeded")
	}

	encrypted, err := u.Crypto.Encrypt([]byte(password))
	if err != nil {
		return err
	}

	for _, p := range userData.Passwords {
		if service == p.Service {
			return errors.New("service already exists")
		}
	}

	userData.Passwords = append(userData.Passwords, entities.PasswordEntry{
		Service:  service,
		Login:    login,
		Password: hex.EncodeToString(encrypted),
	})

	return u.VaultRepo.Write(cfg.User.Name, userData)
}

// GetPasswordUsecase отвечает за получение пароля.
type GetPasswordUsecase struct {
	ConfigRepo  repository.ConfigRepository
	VaultRepo   repository.VaultRepository
	Crypto      CryptoUsecase
	SessionTTL  time.Duration
}

// NewGetPasswordUsecase создаёт новый use case получения пароля.
func NewGetPasswordUsecase(cfgRepo repository.ConfigRepository, vaultRepo repository.VaultRepository, crypto CryptoUsecase, sessionTTL time.Duration) *GetPasswordUsecase {
	return &GetPasswordUsecase{
		ConfigRepo: cfgRepo,
		VaultRepo:  vaultRepo,
		Crypto:     crypto,
		SessionTTL: sessionTTL,
	}
}

// Execute возвращает расшифрованный пароль по названию сервиса.
func (u *GetPasswordUsecase) Execute(service string) (string, error) {
	cfg, err := u.ConfigRepo.Read()
	if err != nil {
		return "", err
	}

	userData, err := u.VaultRepo.Read(cfg.User.Name)
	if err != nil {
		return "", err
	}

	if time.Since(userData.Credentials.LastLoginAt) > u.SessionTTL {
		return "", errors.New("session exceeded")
	}

	for _, p := range userData.Passwords {
		if service == p.Service {
			encrypted, err := hex.DecodeString(p.Password)
			if err != nil {
				return "", err
			}

			decrypted, err := u.Crypto.Decrypt(encrypted)
			if err != nil {
				return "", err
			}

			return string(decrypted), nil
		}
	}

	return "", fmt.Errorf("service %q not found", service)
}

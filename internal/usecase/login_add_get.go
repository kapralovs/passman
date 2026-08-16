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
	"github.com/kapralovs/passman/internal/session"
	"golang.org/x/term"
)

// LoginUsecase отвечает за вход в систему.
type LoginUsecase struct {
	VaultRepo   repository.VaultRepository
	SessionRepo repository.SessionRepository
}

// NewLoginUsecase создаёт новый use case входа.
func NewLoginUsecase(vaultRepo repository.VaultRepository, sessionRepo repository.SessionRepository) *LoginUsecase {
	return &LoginUsecase{
		VaultRepo:   vaultRepo,
		SessionRepo: sessionRepo,
	}
}

// Execute выполняет вход пользователя.
func (u *LoginUsecase) Execute(sess *session.Session) (*session.Session, error) {
	fmt.Print("Password: ")
	password, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()
	if err != nil {
		return nil, err
	}

	hashedPassword := sha256.Sum256(password)

	userData, err := u.VaultRepo.Read(sess.Username)
	if err != nil {
		return nil, err
	}

	if hex.EncodeToString(hashedPassword[:]) != userData.Credentials.Password {
		return nil, errors.New("wrong master password for user")
	}

	userData.Credentials.LastLoginAt = time.Now()
	sess.LastLoginAt = time.Now()
	sess.Trusted = true

	if err := u.VaultRepo.Write(sess.Username, userData); err != nil {
		return nil, err
	}

	return sess, nil
}

// AddPasswordUsecase отвечает за добавление пароля.
type AddPasswordUsecase struct {
	VaultRepo  repository.VaultRepository
	Crypto     CryptoUsecase
	SessionTTL time.Duration
}

// NewAddPasswordUsecase создаёт новый use case добавления пароля.
func NewAddPasswordUsecase(vaultRepo repository.VaultRepository, crypto CryptoUsecase, sessionTTL time.Duration) *AddPasswordUsecase {
	return &AddPasswordUsecase{
		VaultRepo:  vaultRepo,
		Crypto:     crypto,
		SessionTTL: sessionTTL,
	}
}

// Execute добавляет новый пароль.
func (u *AddPasswordUsecase) Execute(sess *session.Session, service, login, password string) (*session.Session, *entities.UserData, error) {
	userData, err := u.VaultRepo.Read(sess.Username)
	if err != nil {
		return nil, nil, err
	}

	if time.Since(userData.Credentials.LastLoginAt) > u.SessionTTL {
		return nil, nil, errors.New("session exceeded")
	}

	encrypted, err := u.Crypto.Encrypt([]byte(password))
	if err != nil {
		return nil, nil, err
	}

	for _, p := range userData.Passwords {
		if service == p.Service {
			return nil, nil, errors.New("service already exists")
		}
	}

	userData.Passwords = append(userData.Passwords, entities.PasswordEntry{
		Service:  service,
		Login:    login,
		Password: hex.EncodeToString(encrypted),
	})

	return sess, userData, nil
}

// UpdateServicePasswordUsecase отвечает за обновление пароля сервиса.
type UpdateServicePasswordUsecase struct {
	VaultRepo  repository.VaultRepository
	Crypto     CryptoUsecase
	SessionTTL time.Duration
}

// NewUpdateServicePasswordUsecase создаёт новый use case обновления пароля.
func NewUpdateServicePasswordUsecase(vaultRepo repository.VaultRepository, crypto CryptoUsecase, sessionTTL time.Duration) *UpdateServicePasswordUsecase {
	return &UpdateServicePasswordUsecase{
		VaultRepo:  vaultRepo,
		Crypto:     crypto,
		SessionTTL: sessionTTL,
	}
}

// Execute обновляет запись пароля по названию сервиса.
func (u *UpdateServicePasswordUsecase) Execute(sess *session.Session, service, login, password string) (*entities.UserData, error) {
	userData, err := u.VaultRepo.Read(sess.Username)
	if err != nil {
		return nil, err
	}

	if time.Since(userData.Credentials.LastLoginAt) > u.SessionTTL {
		return nil, errors.New("session exceeded")
	}

	encrypted, err := u.Crypto.Encrypt([]byte(password))
	if err != nil {
		return nil, err
	}

	for i, p := range userData.Passwords {
		if service == p.Service {
			userData.Passwords[i] = entities.PasswordEntry{
				Service:     service,
				Login:       login,
				Password:    hex.EncodeToString(encrypted),
				URL:         p.URL,
				Description: p.Description,
			}
			return userData, nil
		}
	}

	return nil, fmt.Errorf("service %q not found", service)
}

// GetPasswordUsecase отвечает за получение пароля.
type GetPasswordUsecase struct {
	VaultRepo  repository.VaultRepository
	Crypto     CryptoUsecase
	SessionTTL time.Duration
}

// NewGetPasswordUsecase создаёт новый use case получения пароля.
func NewGetPasswordUsecase(vaultRepo repository.VaultRepository, crypto CryptoUsecase, sessionTTL time.Duration) *GetPasswordUsecase {
	return &GetPasswordUsecase{
		VaultRepo:  vaultRepo,
		Crypto:     crypto,
		SessionTTL: sessionTTL,
	}
}

// Execute возвращает расшифрованный пароль по названию сервиса.
func (u *GetPasswordUsecase) Execute(sess *session.Session, service string) (string, error) {
	userData, err := u.VaultRepo.Read(sess.Username)
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

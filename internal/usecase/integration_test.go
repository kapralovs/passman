package usecase_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/kapralovs/passman/internal/config"
	"github.com/kapralovs/passman/internal/crypto"
	"github.com/kapralovs/passman/internal/entities"
	"github.com/kapralovs/passman/internal/repository"
	"github.com/kapralovs/passman/internal/session"
	"github.com/kapralovs/passman/internal/usecase"
)

func TestFullFlow(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.json")
	sessionPath := filepath.Join(dir, "session.json")

	// Change to temp dir so files are created there
	originalWd, _ := os.Getwd()
	os.Chdir(dir)
	defer os.Chdir(originalWd)

	vaultRepo := repository.NewVaultRepository()
	sessionRepo := repository.NewSessionRepository(sessionPath)

	// 1. Init
	initUC := usecase.NewInitUsecase(configPath)
	if err := initUC.Execute(); err != nil {
		t.Fatalf("init failed: %v", err)
	}

	// 2. Load config and create crypto
	cfg, err := config.Load(configPath)
	if err != nil {
		t.Fatalf("read config failed: %v", err)
	}

	cryptoSvc, err := crypto.NewAESCrypto(cfg.Key)
	if err != nil {
		t.Fatalf("create crypto failed: %v", err)
	}

	sessionTTL := cfg.SessionDuration * time.Minute

	// 3. Add password (bypass signup/login which need terminal)
	// First create a user in vault with current session
	vaultRepo.Write("testuser", &entities.UserData{
		Credentials: entities.Credentials{
			Username:    "testuser",
			LastLoginAt: time.Now(),
		},
	})

	sessionRepo.Save(&session.Session{Username: "testuser"})

	addUC := usecase.NewAddPasswordUsecase(vaultRepo, cryptoSvc, sessionTTL)
	sess, userData, err := addUC.Execute(&session.Session{Username: "testuser"}, "gmail", "user@gmail.com", "super-secret-123")
	if err != nil {
		t.Fatalf("add password failed: %v", err)
	}
	if err := vaultRepo.Write("testuser", userData); err != nil {
		t.Fatalf("write vault failed: %v", err)
	}
	if err := sessionRepo.Save(sess); err != nil {
		t.Fatalf("save session failed: %v", err)
	}

	// 4. Get password
	getUC := usecase.NewGetPasswordUsecase(vaultRepo, cryptoSvc, sessionTTL)
	password, err := getUC.Execute(&session.Session{Username: "testuser"}, "gmail")
	if err != nil {
		t.Fatalf("get password failed: %v", err)
	}

	if password != "super-secret-123" {
		t.Errorf("password mismatch: got %q, want %q", password, "super-secret-123")
	}

	// 5. Try to get non-existent service
	_, err = getUC.Execute(&session.Session{Username: "testuser"}, "nonexistent")
	if err == nil {
		t.Error("expected error for non-existent service")
	}

	// 6. Add another password
	sess, userData, err = addUC.Execute(&session.Session{Username: "testuser"}, "github", "dev@github.com", "ghp_xxxx")
	if err != nil {
		t.Fatalf("add github password failed: %v", err)
	}
	if err := vaultRepo.Write("testuser", userData); err != nil {
		t.Fatalf("write vault failed: %v", err)
	}
	if err := sessionRepo.Save(sess); err != nil {
		t.Fatalf("save session failed: %v", err)
	}

	// 7. Verify both passwords exist
	getUC2 := usecase.NewGetPasswordUsecase(vaultRepo, cryptoSvc, sessionTTL)

	pass1, err := getUC2.Execute(&session.Session{Username: "testuser"}, "gmail")
	if err != nil || pass1 != "super-secret-123" {
		t.Errorf("gmail password mismatch: got %q, want %q", pass1, "super-secret-123")
	}

	pass2, err := getUC2.Execute(&session.Session{Username: "testuser"}, "github")
	if err != nil || pass2 != "ghp_xxxx" {
		t.Errorf("github password mismatch: got %q, want %q", pass2, "ghp_xxxx")
	}
}

func TestFullFlow_SessionExpiry(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.json")

	originalWd, _ := os.Getwd()
	os.Chdir(dir)
	defer os.Chdir(originalWd)

	vaultRepo := repository.NewVaultRepository()

	// Init
	initUC := usecase.NewInitUsecase(configPath)
	if err := initUC.Execute(); err != nil {
		t.Fatalf("init failed: %v", err)
	}

	cfg, _ := config.Load(configPath)
	cryptoSvc, _ := crypto.NewAESCrypto(cfg.Key)

	// Create vault with expired session
	vaultRepo.Write("testuser", &entities.UserData{
		Credentials: entities.Credentials{
			Username:    "testuser",
			LastLoginAt: time.Now().Add(-1 * time.Hour),
		},
	})

	addUC := usecase.NewAddPasswordUsecase(vaultRepo, cryptoSvc, 30*time.Minute)
	_, _, err := addUC.Execute(&session.Session{Username: "testuser"}, "gmail", "user@gmail.com", "pass")
	if err == nil {
		t.Error("expected session exceeded error")
	}

	getUC := usecase.NewGetPasswordUsecase(vaultRepo, cryptoSvc, 30*time.Minute)
	_, err = getUC.Execute(&session.Session{Username: "testuser"}, "gmail")
	if err == nil {
		t.Error("expected session exceeded error")
	}
}

package usecase

import (
	"errors"
	"testing"
	"time"

	"github.com/kapralovs/passman/internal/config"
	"github.com/kapralovs/passman/internal/entities"
)

// --- Mock repositories ---

type mockVaultRepo struct {
	data map[string]*entities.UserData
	err  error
}

func newMockVaultRepo() *mockVaultRepo {
	return &mockVaultRepo{data: make(map[string]*entities.UserData)}
}

func (m *mockVaultRepo) Read(username string) (*entities.UserData, error) {
	if m.err != nil {
		return nil, m.err
	}
	ud, ok := m.data[username]
	if !ok {
		return nil, errors.New("user not found")
	}
	return ud, nil
}

func (m *mockVaultRepo) Write(username string, data *entities.UserData) error {
	if m.err != nil {
		return m.err
	}
	m.data[username] = data
	return nil
}

// --- Mock crypto ---

type mockCrypto struct {
	encryptFunc func([]byte) ([]byte, error)
	decryptFunc func([]byte) ([]byte, error)
}

func (m *mockCrypto) Encrypt(data []byte) ([]byte, error) {
	if m.encryptFunc != nil {
		return m.encryptFunc(data)
	}
	return []byte("encrypted:" + string(data)), nil
}

func (m *mockCrypto) Decrypt(data []byte) ([]byte, error) {
	if m.decryptFunc != nil {
		return m.decryptFunc(data)
	}
	if len(data) > 10 {
		return []byte(string(data[10:])), nil
	}
	return []byte{}, nil
}

// --- Tests ---

func TestInitUsecase_Execute(t *testing.T) {
	dir := t.TempDir()
	configPath := dir + "/config.json"
	uc := NewInitUsecase(configPath)

	err := uc.Execute()
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	cfg, err := config.Load(configPath)
	if err != nil {
		t.Fatalf("load config failed: %v", err)
	}

	if cfg.Key == "" {
		t.Error("expected non-empty key")
	}

	// Key should be 64 hex chars (32 bytes)
	if len(cfg.Key) != 64 {
		t.Errorf("expected key length 64, got %d", len(cfg.Key))
	}

	if cfg.SessionDuration != 30 {
		t.Errorf("expected session duration 30, got %v", cfg.SessionDuration)
	}
}

func TestSignUpUsecase_Execute(t *testing.T) {
	vaultRepo := newMockVaultRepo()
	uc := NewSignUpUsecase(vaultRepo)

	// Pre-populate vault with user
	vaultRepo.data["testuser"] = &entities.UserData{
		Credentials: entities.Credentials{Username: "testuser"},
	}

	cfg := &config.Config{
		User: config.UserConfig{Name: ""},
	}

	// SignUp doesn't accept password via args — it reads from terminal.
	// We can't easily test the full flow without mocking term.ReadPassword.
	// The important thing is the interface is correct.
	_ = cfg
	_ = uc
}

func TestAddPasswordUsecase_SessionExceeded(t *testing.T) {
	vaultRepo := newMockVaultRepo()
	vaultRepo.data["testuser"] = &entities.UserData{
		Credentials: entities.Credentials{
			Username:    "testuser",
			LastLoginAt: time.Now().Add(-1 * time.Hour), // 1 hour ago
		},
	}

	crypto := &mockCrypto{}
	uc := NewAddPasswordUsecase(vaultRepo, crypto, 30*time.Minute)

	cfg := &config.Config{
		User: config.UserConfig{Name: "testuser"},
	}

	_, _, err := uc.Execute(cfg, "gmail", "user@gmail.com", "password123")
	if err == nil {
		t.Error("expected session exceeded error, got nil")
	}

	if err.Error() != "session exceeded" {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestAddPasswordUsecase_Success(t *testing.T) {
	vaultRepo := newMockVaultRepo()
	vaultRepo.data["testuser"] = &entities.UserData{
		Credentials: entities.Credentials{
			Username:    "testuser",
			LastLoginAt: time.Now(),
		},
	}

	crypto := &mockCrypto{}
	uc := NewAddPasswordUsecase(vaultRepo, crypto, 30*time.Minute)

	cfg := &config.Config{
		User: config.UserConfig{Name: "testuser"},
	}

	_, userData, err := uc.Execute(cfg, "gmail", "user@gmail.com", "password123")
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	if len(userData.Passwords) != 1 {
		t.Fatalf("expected 1 password, got %d", len(userData.Passwords))
	}

	if userData.Passwords[0].Service != "gmail" {
		t.Errorf("service mismatch: got %q, want %q", userData.Passwords[0].Service, "gmail")
	}

	if userData.Passwords[0].Login != "user@gmail.com" {
		t.Errorf("login mismatch: got %q, want %q", userData.Passwords[0].Login, "user@gmail.com")
	}
}

func TestAddPasswordUsecase_DuplicateService(t *testing.T) {
	vaultRepo := newMockVaultRepo()
	vaultRepo.data["testuser"] = &entities.UserData{
		Credentials: entities.Credentials{
			Username:    "testuser",
			LastLoginAt: time.Now(),
		},
		Passwords: []entities.PasswordEntry{
			{Service: "gmail", Login: "user@gmail.com", Password: "encrypted"},
		},
	}

	crypto := &mockCrypto{}
	uc := NewAddPasswordUsecase(vaultRepo, crypto, 30*time.Minute)

	cfg := &config.Config{
		User: config.UserConfig{Name: "testuser"},
	}

	_, _, err := uc.Execute(cfg, "gmail", "other@gmail.com", "otherpass")
	if err == nil {
		t.Error("expected duplicate service error, got nil")
	}

	if err.Error() != "service already exists" {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestGetPasswordUsecase_Success(t *testing.T) {
	vaultRepo := newMockVaultRepo()
	vaultRepo.data["testuser"] = &entities.UserData{
		Credentials: entities.Credentials{
			Username:    "testuser",
			LastLoginAt: time.Now(),
		},
		Passwords: []entities.PasswordEntry{
			{Service: "gmail", Login: "user@gmail.com", Password: "656e637279707465643a736563726574313233"},
		},
	}

	crypto := &mockCrypto{}
	uc := NewGetPasswordUsecase(vaultRepo, crypto, 30*time.Minute)

	cfg := &config.Config{
		User: config.UserConfig{Name: "testuser"},
	}

	password, err := uc.Execute(cfg, "gmail")
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	if password != "secret123" {
		t.Errorf("password mismatch: got %q, want %q", password, "secret123")
	}
}

func TestGetPasswordUsecase_ServiceNotFound(t *testing.T) {
	vaultRepo := newMockVaultRepo()
	vaultRepo.data["testuser"] = &entities.UserData{
		Credentials: entities.Credentials{
			Username:    "testuser",
			LastLoginAt: time.Now(),
		},
	}

	crypto := &mockCrypto{}
	uc := NewGetPasswordUsecase(vaultRepo, crypto, 30*time.Minute)

	cfg := &config.Config{
		User: config.UserConfig{Name: "testuser"},
	}

	_, err := uc.Execute(cfg, "nonexistent")
	if err == nil {
		t.Error("expected service not found error, got nil")
	}
}

func TestGetPasswordUsecase_SessionExceeded(t *testing.T) {
	vaultRepo := newMockVaultRepo()
	vaultRepo.data["testuser"] = &entities.UserData{
		Credentials: entities.Credentials{
			Username:    "testuser",
			LastLoginAt: time.Now().Add(-1 * time.Hour),
		},
	}

	crypto := &mockCrypto{}
	uc := NewGetPasswordUsecase(vaultRepo, crypto, 30*time.Minute)

	cfg := &config.Config{
		User: config.UserConfig{Name: "testuser"},
	}

	_, err := uc.Execute(cfg, "gmail")
	if err == nil {
		t.Error("expected session exceeded error, got nil")
	}
}
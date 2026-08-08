package repository

import (
	"os"
	"testing"
	"time"

	"github.com/kapralovs/passman/internal/entities"
)

func TestFileVaultRepository_ReadWrite(t *testing.T) {
	dir := t.TempDir()
	// Change to temp dir so vault files are created there
	originalWd, _ := os.Getwd()
	os.Chdir(dir)
	defer os.Chdir(originalWd)

	repo := NewVaultRepository()

	username := "testuser"
	ud := &entities.UserData{
		Credentials: entities.Credentials{
			Username:    username,
			Password:    "hashed-password",
			LastLoginAt: time.Now(),
		},
		Passwords: []entities.PasswordEntry{
			{
				Service:  "gmail",
				Login:    "user@gmail.com",
				Password: "encrypted-xyz",
			},
		},
	}

	if err := repo.Write(username, ud); err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	// Check file permissions
	info, err := os.Stat(username + "_vault.json")
	if err != nil {
		t.Fatalf("Stat failed: %v", err)
	}
	if info.Mode().Perm() != 0600 {
		t.Errorf("expected file permissions 0600, got %v", info.Mode().Perm())
	}

	readUD, err := repo.Read(username)
	if err != nil {
		t.Fatalf("Read failed: %v", err)
	}

	if readUD.Credentials.Username != ud.Credentials.Username {
		t.Errorf("Username mismatch: got %q, want %q", readUD.Credentials.Username, ud.Credentials.Username)
	}

	if len(readUD.Passwords) != len(ud.Passwords) {
		t.Fatalf("Passwords count mismatch: got %d, want %d", len(readUD.Passwords), len(ud.Passwords))
	}

	if readUD.Passwords[0].Service != ud.Passwords[0].Service {
		t.Errorf("Service mismatch: got %q, want %q", readUD.Passwords[0].Service, ud.Passwords[0].Service)
	}
}

func TestFileVaultRepository_ReadNonExistent(t *testing.T) {
	dir := t.TempDir()
	originalWd, _ := os.Getwd()
	os.Chdir(dir)
	defer os.Chdir(originalWd)

	repo := NewVaultRepository()
	_, err := repo.Read("nonexistent")
	if err == nil {
		t.Error("expected error for non-existent vault, got nil")
	}
}

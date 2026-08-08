package repository

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/kapralovs/passman/internal/entities"
)

// fileVaultRepository реализует VaultRepository для файловой системы.
type fileVaultRepository struct{}

// NewVaultRepository создаёт новое хранилище паролей.
func NewVaultRepository() VaultRepository {
	return &fileVaultRepository{}
}

func (r *fileVaultRepository) Read(username string) (*entities.UserData, error) {
	filename := fmt.Sprintf("%s_vault.json", username)
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	content, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	ud := new(entities.UserData)
	if err = json.Unmarshal(content, ud); err != nil {
		return nil, err
	}

	return ud, nil
}

func (r *fileVaultRepository) Write(username string, data *entities.UserData) error {
	filename := fmt.Sprintf("%s_vault.json", username)
	content, err := json.Marshal(data)
	if err != nil {
		return err
	}

	return os.WriteFile(filename, content, 0600)
}

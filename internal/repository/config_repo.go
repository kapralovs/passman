package repository

import (
	"encoding/json"
	"os"

	"github.com/kapralovs/passman/internal/entities"
)

// fileConfigRepository реализует ConfigRepository для файловой системы.
type fileConfigRepository struct {
	filename string
}

// NewConfigRepository создаёт новый репозиторий конфигурации.
func NewConfigRepository(filename string) ConfigRepository {
	return &fileConfigRepository{filename: filename}
}

func (r *fileConfigRepository) Read() (*entities.Config, error) {
	file, err := os.Open(r.filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	content, err := os.ReadFile(r.filename)
	if err != nil {
		return nil, err
	}

	cfg := new(entities.Config)
	if err = json.Unmarshal(content, cfg); err != nil {
		return nil, err
	}

	return cfg, nil
}

func (r *fileConfigRepository) Write(cfg *entities.Config) error {
	content, err := json.Marshal(cfg)
	if err != nil {
		return err
	}

	return os.WriteFile(r.filename, content, 0600)
}

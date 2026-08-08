package config

import (
	"encoding/json"
	"os"
	"time"
)

// Config представляет глобальную конфигурацию приложения.
type Config struct {
	SessionDuration time.Duration `json:"session_duration"`
	Key             string        `json:"key"`
}

// Load загружает конфигурацию из JSON-файла.
func Load(filename string) (*Config, error) {
	content, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	cfg := new(Config)
	if err = json.Unmarshal(content, cfg); err != nil {
		return nil, err
	}

	return cfg, nil
}

// Save сохраняет конфигурацию в JSON-файл.
func Save(filename string, cfg *Config) error {
	content, err := json.Marshal(cfg)
	if err != nil {
		return err
	}

	return os.WriteFile(filename, content, 0600)
}

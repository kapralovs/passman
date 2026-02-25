// internal/config/config.go
package config

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/kapralovs/passman/internal/models"
)

const (
	defaultConfigFile      = "config.json"
	defaultSessionDuration = 30 * time.Second
)

type Manager struct {
	configFile string
	config     *models.Config
}

func New() *Manager {
	return &Manager{
		configFile: defaultConfigFile,
	}
}

func (m *Manager) Load() error {
	content, err := os.ReadFile(m.configFile)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // Config doesn't exist yet
		}
		return fmt.Errorf("failed to read config file: %w", err)
	}

	cfg := new(models.Config)
	if err = json.Unmarshal(content, cfg); err != nil {
		return fmt.Errorf("failed to parse config file: %w", err)
	}

	m.config = cfg
	return nil
}

func (m *Manager) Save() error {
	if m.config == nil {
		return fmt.Errorf("no config to save")
	}

	content, err := json.MarshalIndent(m.config, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	if err = os.WriteFile(m.configFile, content, 0600); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	return nil
}

func (m *Manager) Get() *models.Config {
	return m.config
}

func (m *Manager) Set(cfg *models.Config) {
	m.config = cfg
}

func (m *Manager) CreateNew() *models.Config {
	m.config = &models.Config{
		SessionDuration: defaultSessionDuration,
	}
	return m.config
}

func (m *Manager) UpdateUser(username string) error {
	if m.config == nil {
		return fmt.Errorf("config not initialized")
	}
	m.config.User.Name = username
	return m.Save()
}

func (m *Manager) UpdateKey(key string) error {
	if m.config == nil {
		return fmt.Errorf("config not initialized")
	}
	m.config.Key = key
	return m.Save()
}

func (m *Manager) GetEncryptionKey() (string, error) {
	if m.config == nil {
		return "", fmt.Errorf("config not initialized")
	}
	if m.config.Key == "" {
		return "", fmt.Errorf("encryption key not set")
	}
	return m.config.Key, nil
}

func (m *Manager) GetCurrentUser() (string, error) {
	if m.config == nil {
		return "", fmt.Errorf("config not initialized")
	}
	if m.config.User.Name == "" {
		return "", fmt.Errorf("no current user")
	}
	return m.config.User.Name, nil
}

func (m *Manager) Exists() bool {
	_, err := os.Stat(m.configFile)
	return err == nil
}

// GetSessionDuration возвращает длительность сессии
func (m *Manager) GetSessionDuration() time.Duration {
	if m.config == nil || m.config.SessionDuration == 0 {
		return defaultSessionDuration
	}
	return m.config.SessionDuration
}

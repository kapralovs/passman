package storage

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/kapralovs/passman/internal/models"
)

type Service struct {
	configFile string
}

func New() *Service {
	return &Service{
		configFile: "config.json",
	}
}

func (s *Service) SaveConfig(cfg *models.Config) error {
	content, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(s.configFile, content, 0600)
}

func (s *Service) LoadConfig() (*models.Config, error) {
	content, err := os.ReadFile(s.configFile)
	if err != nil {
		return nil, err
	}

	cfg := new(models.Config)
	if err = json.Unmarshal(content, cfg); err != nil {
		return nil, err
	}

	return cfg, nil
}

func (s *Service) SaveUserData(username string, data *models.UserData) error {
	filename := fmt.Sprintf("%s_vault.json", username)
	content, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(filename, content, 0600)
}

func (s *Service) LoadUserData(username string) (*models.UserData, error) {
	filename := fmt.Sprintf("%s_vault.json", username)
	content, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	ud := new(models.UserData)
	if err = json.Unmarshal(content, ud); err != nil {
		return nil, err
	}

	return ud, nil
}

func (s *Service) UserExists(username string) bool {
	filename := fmt.Sprintf("%s_vault.json", username)
	_, err := os.Stat(filename)
	return err == nil
}

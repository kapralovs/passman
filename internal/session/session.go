package session

import (
	"errors"
	"time"

	"github.com/kapralovs/passman/internal/models"
)

type Manager struct {
	location *time.Location
}

func New() (*Manager, error) {
	loc, err := time.LoadLocation("Europe/Moscow")
	if err != nil {
		return nil, err
	}

	return &Manager{
		location: loc,
	}, nil
}

func (m *Manager) Check(cfg *models.Config, creds models.Credentials) error {
	if time.Since(creds.LastLoginAt.In(m.location)) > cfg.SessionDuration {
		return errors.New("session expired")
	}
	return nil
}

func (m *Manager) Update(creds *models.Credentials) {
	creds.LastLoginAt = time.Now()
}

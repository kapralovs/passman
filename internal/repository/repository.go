package repository

import "github.com/kapralovs/passman/internal/entities"

// ConfigRepository определяет интерфейс для работы с конфигурацией.
type ConfigRepository interface {
	Read() (*entities.Config, error)
	Write(cfg *entities.Config) error
}

// VaultRepository определяет интерфейс для работы с хранилищем паролей пользователя.
type VaultRepository interface {
	Read(username string) (*entities.UserData, error)
	Write(username string, data *entities.UserData) error
}

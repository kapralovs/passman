package repository

import "github.com/kapralovs/passman/internal/entities"

// VaultRepository определяет интерфейс для работы с хранилищем паролей пользователя.
type VaultRepository interface {
	Read(username string) (*entities.UserData, error)
	Write(username string, data *entities.UserData) error
}

package session

import (
	"encoding/json"
	"os"
	"time"
)

// Session хранит динамическое состояние пользователя (сессия).
type Session struct {
	Username    string    `json:"username"`
	LastLoginAt time.Time `json:"last_login_at"`
	Trusted     bool      `json:"trusted"`
}

// Load загружает сессию из JSON-файла.
// Если файл не найден, возвращает пустую сессию.
func Load(filename string) (*Session, error) {
	content, err := os.ReadFile(filename)
	if err != nil {
		if os.IsNotExist(err) {
			return &Session{}, nil
		}
		return nil, err
	}

	var s Session
	if err = json.Unmarshal(content, &s); err != nil {
		return nil, err
	}

	return &s, nil
}

// Save сохраняет сессию в JSON-файл.
func Save(filename string, s *Session) error {
	content, err := json.Marshal(s)
	if err != nil {
		return err
	}

	return os.WriteFile(filename, content, 0600)
}

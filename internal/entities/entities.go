package entities

import "time"

// Config представляет глобальную конфигурацию приложения.
type Config struct {
	User            UserConfig    `json:"user_config"`
	SessionDuration time.Duration `json:"session_duration"`
	Key             string        `json:"key"`
}

// UserConfig содержит информацию о текущем пользователе.
type UserConfig struct {
	Name    string `json:"name"`
	Trusted bool   `json:"trusted"`
}

// UserData представляет хранилище данных конкретного пользователя.
type UserData struct {
	Credentials Credentials     `json:"credentials"`
	Passwords   []PasswordEntry `json:"passwords"`
}

// Credentials содержит учётные данные пользователя.
type Credentials struct {
	Username    string    `json:"username"`
	Password    string    `json:"password"`
	LastLoginAt time.Time `json:"last_login_at"`
}

// PasswordEntry представляет одну запись пароля.
type PasswordEntry struct {
	Service     string `json:"service"`
	Login       string `json:"login"`
	Password    string `json:"password"`
	URL         string `json:"url"`
	Description string `json:"description"`
}

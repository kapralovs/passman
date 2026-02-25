package models

import "time"

type Config struct {
	User            UserConfig    `json:"user_config"`
	SessionDuration time.Duration `json:"session_duration"`
	Key             string        `json:"key"`
}

type UserConfig struct {
	Name    string `json:"name"`
	Trusted bool   `json:"trusted"`
}

type UserData struct {
	Credentials Credentials     `json:"credentials"`
	Passwords   []PasswordEntry `json:"passwords"`
}

type Credentials struct {
	Username    string    `json:"username"`
	Password    string    `json:"password"`
	LastLoginAt time.Time `json:"last_login_at"`
}

type PasswordEntry struct {
	Service     string `json:"service"`
	Login       string `json:"login"`
	Password    string `json:"password"`
	URL         string `json:"url"`
	Description string `json:"description"`
}

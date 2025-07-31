package main_test

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"
	"time"

	"golang.org/x/term"
)

type Config struct {
	User            UserConfig
	SessionDuration time.Duration
	Key             string
}

type UserConfig struct {
	Name string
}

// Фиктивный объект Config для тестирования
var testCfg = Config{
	User:            UserConfig{Name: "test-user"},
	SessionDuration: time.Second * 30,
	Key:             "",
}

// Заглушка для ввода пароля
var fakeTermReadPassword func(string) ([]byte, error)

// Перехват вывода в stdout
var outputBuffer bytes.Buffer

// Функция setupTest настраивает глобальные состояния и заглушки
func setupTest(t *testing.T) {
	outputBuffer.Reset()
	fakeTermReadPassword = func(prompt string) ([]byte, error) {
		t.Logf("Mock input received prompt '%v'", prompt)
		return []byte("mock-password"), nil // Возвращаем фиксированный моковски пароль
	}
	term.ReadPassword = fakeTermReadPassword
	os.Stdout = &outputBuffer
}

// Функция teardownTest очищает состояние после теста
func teardownTest(t *testing.T) {
	term.ReadPassword = term.ReadPasswordImpl
	os.Stdout = os.Stdout
}

// Тестовые вспомогательные функции
func TestMain(m *testing.M) {
	setupTest(nil)
	code := m.Run()
	teardownTest(nil)
	os.Exit(code)
}

// Вспомогательная функция для генерации фиктивного конфига
func createTestConfigFile(t *testing.T) {
	cfgBytes, err := json.Marshal(testCfg)
	if err != nil {
		t.Fatalf("Failed to marshal test config: %v", err)
	}
	err = os.WriteFile("config.json", cfgBytes, 0644)
	if err != nil {
		t.Fatalf("Failed to write test config file: %v", err)
	}
}

// Удаляем временный конфиг после тестов
func removeTestFiles() {
	os.Remove("config.json")
	os.Remove("test-user_vault.json")
}

// Готовимся к запуску тестов
func prepareForTests(t *testing.T) {
	createTestConfigFile(t)
	removeTestFiles()
}

// Завершаем тестирование
func finishTests(t *testing.T) {
	removeTestFiles()
}

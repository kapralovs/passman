package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"time"
)

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

const (
	CommandInit   = "init"
	CommandSignUp = "signup"
	CommandLogin  = "login"
	CommandAdd    = "add"
)

func main() {
	//Input
	if err := handleCommand(); err != nil {
		log.Println("handle command: ", err)
	}

	// if len(os.Args) < 4 {
	// 	fmt.Println("not enough arguments")
	// 	return
	// }

	// decrypted, err := decrypt(key, encrypted)
	// if err != nil {
	// 	log.Fatal(err)
	// }

	// fmt.Printf("Decrypted: %s\n", decrypted)
}

func handleCommand() error {
	switch os.Args[1] {
	case CommandInit:
		return initApp()
	case CommandSignUp:
		return signUp()
	case CommandLogin:
		return login()
	case CommandAdd:
		return addPassword()
		// case CommandGet:
	}

	return nil
}

func initApp() error {
	cfg := Config{
		SessionDuration: time.Second * 30,
	}

	content, err := json.Marshal(&cfg)
	if err != nil {
		return err
	}

	file, err := os.Create("config.json")
	if err != nil {
		return err
	}
	defer file.Close()

	if _, err := file.Write(content); err != nil {
		return err
	}

	return nil
}

func signUp() error {
	username, password := parseCredentialsFlags(CommandSignUp)
	hashedPassword := sha256.Sum256([]byte(password))
	// fmt.Printf("%x\n", hashedPassword)

	if err := checkUserData(username); err != nil {
		return err
	}

	ud := &UserData{
		Credentials: Credentials{
			Username:    username,
			Password:    fmt.Sprintf("%x", hashedPassword),
			LastLoginAt: time.Now(),
		},
		Passwords: []PasswordEntry{},
	}

	updatedUserDataContent, err := json.Marshal(ud)
	if err != nil {
		return err
	}

	cfg, err := getConfig()
	if err != nil {
		return err
	}

	cfg.User.Name = username

	if err = updateConfig(cfg); err != nil {
		return err
	}

	filename := fmt.Sprintf("%s_vault.json", username)
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	_, err = file.Write(updatedUserDataContent)
	if err != nil {
		return err
	}

	fmt.Println("Sign up succes!")

	return nil
}

func login() error {
	_, password := parseCredentialsFlags(CommandSignUp)
	hashedPassword := sha256.Sum256([]byte(password))
	// fmt.Printf("%x\n", hashedPassword)

	// Get current user name
	cfg, err := getConfig()
	if err != nil {
		return err
	}

	// Get user data
	userData, err := getUserData(cfg.User.Name)
	if err != nil {
		return err
	}

	if fmt.Sprintf("%x", hashedPassword) != userData.Credentials.Password {
		return errors.New("wrong master password for user")
	}

	fmt.Println("Login succes!")

	return nil
}

func addPassword() error {
	// Get current user name
	cfg, err := getConfig()
	if err != nil {
		return err
	}

	// Get user data
	userData, err := getUserData(cfg.User.Name)
	if err != nil {
		return err
	}

	// Check login sessio
	if err = checkSession(cfg, userData.Credentials); err != nil {
		return err
	}

	service, login, password := parseNewPasswordFlags()

	key, err := hex.DecodeString(cfg.Key)
	if err != nil {
		return err
	}

	// Encrypt password
	encrypted, err := encrypt(key, []byte(password))
	if err != nil {
		log.Fatal(err)
	}

	// fmt.Printf("Encrypted: %s\n", hex.EncodeToString(encrypted))

	// Check if service exists
	for _, p := range userData.Passwords {
		if service == p.Service {
			return errors.New("service already exists")
		}
	}

	// Save to file
	userData.Passwords = append(userData.Passwords, PasswordEntry{
		Service:  service,
		Login:    login,
		Password: hex.EncodeToString(encrypted),
	})

	updatedUserDataContent, err := json.Marshal(userData)
	if err != nil {
		return err
	}

	filename := fmt.Sprintf("%s_vault.json", userData.Credentials.Username)
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	_, err = file.Write(updatedUserDataContent)
	if err != nil {
		return err
	}

	fmt.Println("Added")

	return nil
}

func getConfig() (*Config, error) {
	file, err := os.Open("config.json")
	if err != nil {
		return nil, err
	}
	defer file.Close()

	configContent, err := io.ReadAll(file)
	if err != nil {
		return nil, err
	}

	cfg := new(Config)

	if err = json.Unmarshal(configContent, cfg); err != nil {
		return nil, err
	}

	return cfg, nil
}

func updateConfig(cfg *Config) error {
	content, err := json.Marshal(&cfg)
	if err != nil {
		return err
	}

	file, err := os.Create("config.json")
	if err != nil {
		return err
	}
	defer file.Close()

	if _, err := file.Write(content); err != nil {
		return err
	}

	return nil
}

func checkSession(cfg *Config, creds Credentials) error {
	if time.Since(creds.LastLoginAt) > cfg.SessionDuration {
		return errors.New("session exceeded")
	}

	return nil
}

func getUserData(username string) (*UserData, error) {
	filename := fmt.Sprintf("%s_vault.json", username)

	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	content, err := io.ReadAll(file)
	if err != nil {
		return nil, err
	}

	ud := new(UserData)

	if err = json.Unmarshal(content, &ud); err != nil {
		return nil, err
	}

	// 	if ud.Credentials.Username != username {
	// 	return nil, errors.New("no user data found")
	// }

	return ud, nil
}

func checkUserData(username string) error {
	filename := fmt.Sprintf("%s_vault.json", username)

	file, err := os.Open(filename)
	if err == nil {
		return err
	}
	defer file.Close()

	return nil
}

func parseCredentialsFlags(operation string) (string, string) {
	flagSet := flag.NewFlagSet(operation, flag.ExitOnError)

	usernameFlag := flagSet.String("username", "", "Auth username")
	passwordFlag := flagSet.String("password", "", "Auth password")

	flagSet.Parse(os.Args[2:])

	var username, password string

	username = getStringFlagValue(usernameFlag)
	password = getStringFlagValue(passwordFlag)

	return username, password
}

func parseNewPasswordFlags() (string, string, string) {
	flagSet := flag.NewFlagSet(CommandAdd, flag.ExitOnError)

	serviceFlag := flagSet.String("service", "", "Service name")
	loginFlag := flagSet.String("login", "", "Service login")
	passwordFlag := flagSet.String("password", "", "Service password")

	flagSet.Parse(os.Args[2:])

	service := getStringFlagValue(serviceFlag)
	login := getStringFlagValue(loginFlag)
	password := getStringFlagValue(passwordFlag)

	return service, login, password
}

func getStringFlagValue(val *string) string {
	var parsedVal string

	if val != nil {
		parsedVal = *val
	}

	return parsedVal
}

func encrypt(key, data []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		log.Fatal(err)
	}

	paddedData := pkcs7Pad(data, aes.BlockSize)

	ciphertext := make([]byte, aes.BlockSize+len(paddedData))

	iv := ciphertext[:aes.BlockSize]
	if _, err = io.ReadFull(rand.Reader, iv); err != nil {
		log.Fatal("create initialization vector", err)
	}

	encrypter := cipher.NewCBCEncrypter(block, iv)

	encrypter.CryptBlocks(ciphertext[aes.BlockSize:], paddedData)

	return ciphertext, nil
}

func decrypt(key, encryptedData []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		log.Fatal(err)
	}

	if len(encryptedData) < aes.BlockSize {
		return nil, errors.New("encrypted text too short")
	}

	iv := encryptedData[:aes.BlockSize]
	actualEncryptedData := encryptedData[aes.BlockSize:]

	decrypter := cipher.NewCBCDecrypter(block, iv)

	plaintext := make([]byte, len(actualEncryptedData))

	decrypter.CryptBlocks(plaintext, actualEncryptedData)

	plaintext, err = pkcs7Unpad(plaintext)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

func pkcs7Pad(data []byte, blockSize int) []byte {
	padding := blockSize - len(data)%blockSize
	padText := bytes.Repeat([]byte{byte(padding)}, padding)

	return append(data, padText...)
}

func pkcs7Unpad(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, errors.New("empty data")
	}

	padding := int(data[len(data)-1])
	if padding > len(data) || padding == 0 {
		return nil, errors.New("invalid padding")
	}

	for i := len(data) - padding; i < len(data); i++ {
		if int(data[i]) != padding {
			return nil, errors.New("invalid padding")
		}
	}

	return data[:len(data)-padding], nil
}

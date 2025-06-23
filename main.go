package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"time"
)

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

type Storage map[string]UserData

const (
	CommandSignUp = "signup"
	CommandLogin  = "login"
)

var (
	// username = flag.String("username", "", "passman login -username=<username>")
	// password = flag.String("password", "", "passman login -password=<password>")
	strg = make(Storage)
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

	// pe := PasswordEntry{
	// 	Service:  os.Args[1],
	// 	Login:    os.Args[2],
	// 	Password: os.Args[3],
	// }

	key := make([]byte, 32)
	_, err := io.ReadFull(rand.Reader, key)
	if err != nil {
		log.Fatal("create 256-bit key", err)
	}

	// fmt.Println("Key:", hex.EncodeToString(key))

	//Encrypt
	// encrypted, err := encrypt(key, []byte(pe.Password))
	// if err != nil {
	// 	log.Fatal(err)
	// }

	// fmt.Printf("Encrypted: %s\n", hex.EncodeToString(encrypted))

	// decrypted, err := decrypt(key, encrypted)
	// if err != nil {
	// 	log.Fatal(err)
	// }

	// fmt.Printf("Decrypted: %s\n", decrypted)
	fmt.Println("saved")
}

func handleCommand() error {
	switch os.Args[1] {
	case CommandSignUp:
		return handleSignUp()
	case CommandLogin:
		return handleLogin()
		// case CommandAdd:
		// case CommandGet:
	}

	return nil
}

func handleSignUp() error {
	flagSet := flag.NewFlagSet("signup", flag.ExitOnError)

	usernameFlag := flagSet.String("username", "", "passman login -username=<username>")
	passwordFlag := flagSet.String("password", "", "passman login -password=<password>")

	flagSet.Parse(os.Args[2:])

	var (
		username, password string
		hashedPassword     [32]byte
	)

	username = getStringFlagValue(usernameFlag)
	password = getStringFlagValue(passwordFlag)
	hashedPassword = sha256.Sum256([]byte(password))
	// fmt.Printf("%x\n", hashedPassword)

	if _, ok := strg[username]; ok {
		return errors.New("user already exists")
	}
	strg[username] = UserData{
		Credentials: Credentials{
			Username:    username,
			Password:    fmt.Sprintf("%x", hashedPassword),
			LastLoginAt: time.Now(),
		},
		Passwords: []PasswordEntry{},
	}

	fmt.Println("Sign up succes!")

	return nil
}

func handleLogin() error {
	flagSet := flag.NewFlagSet("login", flag.ExitOnError)

	usernameFlag := flagSet.String("username", "", "Login username")
	passwordFlag := flagSet.String("password", "", "Login password")

	flagSet.Parse(os.Args[2:])

	var (
		username, password string
		hashedPassword     [32]byte
	)

	username = getStringFlagValue(usernameFlag)
	password = getStringFlagValue(passwordFlag)
	hashedPassword = sha256.Sum256([]byte(password))
	// fmt.Printf("%x\n", hashedPassword)

	if _, ok := strg[username]; !ok {
		return errors.New("no users found")
	}
	if string(hashedPassword[:]) != strg[username].Credentials.Password {
		return errors.New("wrong master password for user")
	}

	fmt.Println("Login succes!")

	return nil
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

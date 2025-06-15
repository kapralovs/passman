package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"os"
)

type UserData struct {
	Username  string          `json:"username"`
	Passwords []PasswordEntry `json:"passwords"`
}

type PasswordEntry struct {
	Service     string `json:"service"`
	Login       string `json:"login"`
	Password    string `json:"password"`
	URL         string `json:"url"`
	Description string `json:"description"`
}

func main() {
	// if err := godotenv.Load(); err != nil {
	// 	log.Fatal(err)
	// }

	key := make([]byte, 32)
	_, err := io.ReadFull(rand.Reader, key)
	if err != nil {
		log.Fatal("create 256-bit key", err)
	}

	fmt.Println("Key:", string(key))

	//Input
	if len(os.Args) < 4 {
		fmt.Println("not enough arguments")
		return
	}

	pe := PasswordEntry{
		Service:  os.Args[1],
		Login:    os.Args[2],
		Password: os.Args[3],
	}

	// key := []byte(os.Getenv("SECRET_KEY"))

	//Encrypt
	encrypted, err := encrypt(key, []byte(pe.Password))
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(string(encrypted))

	//Save to storage
	// f, err := os.Create("passman_data.json")
	// if err != nil {
	// 	log.Fatal(err)
	// }
	// defer f.Close()

	// if err := json.NewEncoder(f).
	// 	Encode(&pe); err != nil {
	// 	log.Fatal(err)
	// }

	fmt.Println("saved")
}

func encrypt(key, data []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		log.Fatal(err)
	}

	ciphertext := make([]byte, aes.BlockSize+len(data))

	iv := ciphertext[:aes.BlockSize]
	_, err = io.ReadFull(rand.Reader, iv)
	if err != nil {
		log.Fatal("create initialization vector", err)
	}

	encrypter := cipher.NewCBCEncrypter(block, iv)

	encrypter.CryptBlocks(ciphertext[aes.BlockSize:], data)

	fmt.Printf("Encrypted: %s\n", hex.EncodeToString(ciphertext))

	return ciphertext, nil
}

// func decrypt(key, encryptedData []byte) ([]byte, error) {
// 	return decrypted, nil
// }

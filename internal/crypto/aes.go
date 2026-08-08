package crypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"

	"github.com/kapralovs/passman/internal/usecase"
)

// AESCrypto реализует usecase.CryptoUsecase с использованием AES-256-CBC.
type AESCrypto struct {
	key []byte
}

// NewAESCrypto создаёт новый криптографический сервис из hex-ключа.
func NewAESCrypto(hexKey string) (usecase.CryptoUsecase, error) {
	key, err := hex.DecodeString(hexKey)
	if err != nil {
		return nil, err
	}
	return &AESCrypto{key: key}, nil
}

// Encrypt шифрует данные через AES-256-CBC с PKCS7.
func (c *AESCrypto) Encrypt(data []byte) ([]byte, error) {
	block, err := aes.NewCipher(c.key)
	if err != nil {
		return nil, err
	}

	padded := pkcs7Pad(data, aes.BlockSize)

	ciphertext := make([]byte, aes.BlockSize+len(padded))
	iv := ciphertext[:aes.BlockSize]
	if _, err = io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	encrypter := cipher.NewCBCEncrypter(block, iv)
	encrypter.CryptBlocks(ciphertext[aes.BlockSize:], padded)

	return ciphertext, nil
}

// Decrypt расшифровывает данные через AES-256-CBC с PKCS7.
func (c *AESCrypto) Decrypt(encryptedData []byte) ([]byte, error) {
	block, err := aes.NewCipher(c.key)
	if err != nil {
		return nil, err
	}

	if len(encryptedData) < aes.BlockSize {
		return nil, errors.New("encrypted text too short")
	}

	iv := encryptedData[:aes.BlockSize]
	actual := encryptedData[aes.BlockSize:]

	decrypter := cipher.NewCBCDecrypter(block, iv)
	plaintext := make([]byte, len(actual))
	decrypter.CryptBlocks(plaintext, actual)

	return pkcs7Unpad(plaintext)
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

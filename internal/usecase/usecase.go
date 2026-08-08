package usecase

// CryptoUsecase — публичный интерфейс для шифрования/дешифрования.
type CryptoUsecase interface {
	Encrypt(data []byte) ([]byte, error)
	Decrypt(data []byte) ([]byte, error)
}

package usecase

// CryptoUsecase определяет интерфейс для шифрования и дешифрования.
type CryptoUsecase interface {
	Encrypt(data []byte) ([]byte, error)
	Decrypt(data []byte) ([]byte, error)
}

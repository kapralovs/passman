package crypto

import (
	"testing"
)

func TestAESCrypto_EncryptDecrypt(t *testing.T) {
	key := "0102030405060708091011121314151617181920212223242526272829303132" // 32 bytes
	crypto, err := NewAESCrypto(key)
	if err != nil {
		t.Fatalf("failed to create crypto: %v", err)
	}

	original := []byte("my-secure-password-123")

	encrypted, err := crypto.Encrypt(original)
	if err != nil {
		t.Fatalf("encrypt failed: %v", err)
	}

	// Encrypted data should be different from original and longer (IV + padded data)
	if len(encrypted) <= len(original) {
		t.Errorf("encrypted data should be longer than original, got %d vs %d", len(encrypted), len(original))
	}

	decrypted, err := crypto.Decrypt(encrypted)
	if err != nil {
		t.Fatalf("decrypt failed: %v", err)
	}

	if string(decrypted) != string(original) {
		t.Errorf("decrypted mismatch: got %q, want %q", string(decrypted), string(original))
	}
}

func TestAESCrypto_EncryptDifferentEachTime(t *testing.T) {
	key := "0102030405060708091011121314151617181920212223242526272829303132"
	crypto, err := NewAESCrypto(key)
	if err != nil {
		t.Fatalf("failed to create crypto: %v", err)
	}

	data := []byte("same-password")

	enc1, err := crypto.Encrypt(data)
	if err != nil {
		t.Fatalf("encrypt 1 failed: %v", err)
	}

	enc2, err := crypto.Encrypt(data)
	if err != nil {
		t.Fatalf("encrypt 2 failed: %v", err)
	}

	// Each encryption should produce different ciphertext (due to random IV)
	if string(enc1) == string(enc2) {
		t.Error("encrypt should produce different ciphertext each time (random IV)")
	}

	// But both should decrypt to the same value
	dec1, err := crypto.Decrypt(enc1)
	if err != nil {
		t.Fatalf("decrypt 1 failed: %v", err)
	}
	dec2, err := crypto.Decrypt(enc2)
	if err != nil {
		t.Fatalf("decrypt 2 failed: %v", err)
	}

	if string(dec1) != string(dec2) || string(dec1) != string(data) {
		t.Errorf("both decryptions should match original, got %q and %q", string(dec1), string(dec2))
	}
}

func TestAESCrypto_DecryptInvalidData(t *testing.T) {
	key := "0102030405060708091011121314151617181920212223242526272829303132"
	crypto, err := NewAESCrypto(key)
	if err != nil {
		t.Fatalf("failed to create crypto: %v", err)
	}

	tests := []struct {
		name    string
		data    []byte
		wantErr bool
	}{
		{
			name:    "empty data",
			data:    []byte{},
			wantErr: true,
		},
		{
			name:    "too short (less than IV)",
			data:    []byte{1, 2, 3},
			wantErr: true,
		},
		{
			name:    "invalid padding",
			data:    []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 5},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := crypto.Decrypt(tt.data)
			if (err != nil) != tt.wantErr {
				t.Errorf("Decrypt() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestAESCrypto_InvalidKey(t *testing.T) {
	_, err := NewAESCrypto("not-a-valid-hex-key!!!")
	if err == nil {
		t.Error("expected error for invalid hex key, got nil")
	}
}

func TestAESCrypto_EmptyData(t *testing.T) {
	key := "0102030405060708091011121314151617181920212223242526272829303132"
	crypto, err := NewAESCrypto(key)
	if err != nil {
		t.Fatalf("failed to create crypto: %v", err)
	}

	// Empty password should still encrypt/decrypt correctly
	encrypted, err := crypto.Encrypt([]byte{})
	if err != nil {
		t.Fatalf("encrypt empty failed: %v", err)
	}

	decrypted, err := crypto.Decrypt(encrypted)
	if err != nil {
		t.Fatalf("decrypt empty failed: %v", err)
	}

	if len(decrypted) != 0 {
		t.Errorf("expected empty decrypted data, got %q", string(decrypted))
	}
}

func TestAESCrypto_LongData(t *testing.T) {
	key := "0102030405060708091011121314151617181920212223242526272829303132"
	crypto, err := NewAESCrypto(key)
	if err != nil {
		t.Fatalf("failed to create crypto: %v", err)
	}

	// Data longer than AES block size (16 bytes)
	original := make([]byte, 1024)
	for i := range original {
		original[i] = byte(i % 256)
	}

	encrypted, err := crypto.Encrypt(original)
	if err != nil {
		t.Fatalf("encrypt long failed: %v", err)
	}

	decrypted, err := crypto.Decrypt(encrypted)
	if err != nil {
		t.Fatalf("decrypt long failed: %v", err)
	}

	if string(decrypted) != string(original) {
		t.Error("long data decrypt mismatch")
	}
}

package server

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
)

// DeriveCryptoIdentity computes the Crypto Username as the first 10 hex digits of
// SHA-256(salt + username + password), and the full 32-byte SHA-256(username + password)
// hash as the symmetric crypto key.
func DeriveCryptoIdentity(salt, username, password string) (string, []byte) {
	hUser := sha256.New()
	hUser.Write([]byte(salt))
	hUser.Write([]byte(username))
	hUser.Write([]byte(password))
	userSum := hUser.Sum(nil)
	cryptoUsername := hex.EncodeToString(userSum)[:10]

	hKey := sha256.New()
	hKey.Write([]byte(username))
	hKey.Write([]byte(password))
	keySum := hKey.Sum(nil)

	return cryptoUsername, keySum
}

// HashPassword computes the lowercase hex-encoded SHA-256 hash of (salt + password).
func HashPassword(salt, password string) string {
	h := sha256.New()
	h.Write([]byte(salt))
	h.Write([]byte(password))
	return hex.EncodeToString(h.Sum(nil))
}


// EncryptMessage encrypts plaintext using AES-256-GCM with the provided 32-byte key
// and returns its standard Base64 representation (nonce prepended to ciphertext).
func EncryptMessage(plaintext string, key []byte) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("failed to create AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create GCM: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("failed to generate nonce: %w", err)
	}

	sealed := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return base64.StdEncoding.EncodeToString(sealed), nil
}

// DecryptMessage decrypts a Base64-encoded AES-256-GCM ciphertext using the provided key.
func DecryptMessage(b64Ciphertext string, key []byte) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(b64Ciphertext)
	if err != nil {
		return "", fmt.Errorf("invalid base64 ciphertext: %w", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("failed to create AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create GCM: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(raw) < nonceSize {
		return "", fmt.Errorf("ciphertext too short")
	}

	nonce := raw[:nonceSize]
	ciphertext := raw[nonceSize:]

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", fmt.Errorf("decryption failed: %w", err)
	}

	return string(plaintext), nil
}

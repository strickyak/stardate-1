package server

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

func TestDeriveCryptoIdentity(t *testing.T) {
	salt := "some-arbitrary-string"
	username := "spock"
	password := "starfleet_extra1234"

	cryptoUser, key := DeriveCryptoIdentity(salt, username, password)

	if len(cryptoUser) != 10 {
		t.Fatalf("expected 10 hex digits for crypto username, got %d (%q)", len(cryptoUser), cryptoUser)
	}

	if len(key) != 32 {
		t.Fatalf("expected 32-byte key, got %d", len(key))
	}

	// Verify against manual sha256(salt + username + password) calculation
	expectedHash := sha256.Sum256([]byte(salt + username + password))
	expectedHex := hex.EncodeToString(expectedHash[:])
	expectedUser := expectedHex[:10]

	if cryptoUser != expectedUser {
		t.Errorf("expected crypto username %s, got %s", expectedUser, cryptoUser)
	}

	for _, c := range cryptoUser {
		if !strings.ContainsRune("0123456789abcdef", c) {
			t.Errorf("invalid hex digit in crypto username: %c", c)
		}
	}
}

func TestEncryptDecryptMessage(t *testing.T) {
	_, key := DeriveCryptoIdentity("salt123", "kirk", "starfleet_enterprise1")
	message := "Personal log: Encountered mysterious space probe."

	b64Ciphertext, err := EncryptMessage(message, key)
	if err != nil {
		t.Fatalf("EncryptMessage failed: %v", err)
	}

	if b64Ciphertext == message {
		t.Fatal("ciphertext should not equal plaintext")
	}

	decrypted, err := DecryptMessage(b64Ciphertext, key)
	if err != nil {
		t.Fatalf("DecryptMessage failed: %v", err)
	}

	if decrypted != message {
		t.Fatalf("expected %q, got %q", message, decrypted)
	}

	// Test with wrong key
	_, wrongKey := DeriveCryptoIdentity("salt123", "khan", "starfleet_mutiny1234")
	_, err = DecryptMessage(b64Ciphertext, wrongKey)
	if err == nil {
		t.Fatal("expected decryption failure with wrong key, but succeeded")
	}

	// Test with invalid base64
	_, err = DecryptMessage("not-valid-base64!@#$", key)
	if err == nil {
		t.Fatal("expected error with invalid base64, but succeeded")
	}
}

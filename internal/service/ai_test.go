package service

import "testing"

func TestEncryptDecryptApiKey(t *testing.T) {
	// 32-byte key in hex (64 hex chars)
	secret := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	plaintext := "sk-test-api-key-12345"

	encrypted := EncryptApiKey(plaintext, secret)
	if encrypted == "" {
		t.Fatal("encryption returned empty string")
	}

	decrypted := DecryptApiKey(encrypted, secret)
	if decrypted != plaintext {
		t.Errorf("decrypted = %q, want %q", decrypted, plaintext)
	}
}

func TestEncryptApiKeyEmptyInputs(t *testing.T) {
	if EncryptApiKey("", "abc") != "" {
		t.Error("expected empty for empty plaintext")
	}
	if EncryptApiKey("test", "") != "" {
		t.Error("expected empty for empty secret")
	}
}

func TestDecryptApiKeyInvalid(t *testing.T) {
	if DecryptApiKey("not:valid:data", "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef") != "" {
		t.Error("expected empty for invalid ciphertext")
	}
}

func TestDecryptApiKeyWrongKey(t *testing.T) {
	secret1 := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	secret2 := "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"

	encrypted := EncryptApiKey("test-key", secret1)
	decrypted := DecryptApiKey(encrypted, secret2)
	if decrypted != "" {
		t.Error("expected empty for wrong key")
	}
}

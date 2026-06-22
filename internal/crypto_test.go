package internal

import (
	"bytes"
	"testing"
)

func TestEncryptDecryptRoundTrip(t *testing.T) {
	key := DeriveKey("test-passphrase")
	plaintext := []byte("hello, encrypted world!")

	encrypted, err := Encrypt(key, plaintext)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	if bytes.Equal(encrypted, plaintext) {
		t.Fatal("encrypted data should differ from plaintext")
	}

	decrypted, err := Decrypt(key, encrypted)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	if !bytes.Equal(decrypted, plaintext) {
		t.Fatalf("decrypted != original: got %q, want %q", decrypted, plaintext)
	}
}

func TestEncryptProducesUniqueNonce(t *testing.T) {
	key := DeriveKey("test")
	plaintext := []byte("same input")

	enc1, _ := Encrypt(key, plaintext)
	enc2, _ := Encrypt(key, plaintext)

	if bytes.Equal(enc1, enc2) {
		t.Fatal("two encrypts of same plaintext should produce different ciphertext (random nonce)")
	}
}

func TestDecryptWithWrongKey(t *testing.T) {
	key1 := DeriveKey("password1")
	key2 := DeriveKey("password2")

	encrypted, _ := Encrypt(key1, []byte("secret"))
	_, err := Decrypt(key2, encrypted)
	if err == nil {
		t.Fatal("decrypt with wrong key should fail")
	}
}

func TestHandshakeTokenDeterministic(t *testing.T) {
	key := DeriveKey("my-key")
	token1 := HandshakeToken(key)
	token2 := HandshakeToken(key)

	if token1 != token2 {
		t.Fatal("same key should produce same token")
	}
}

func TestHandshakeTokenDifferentKeys(t *testing.T) {
	token1 := HandshakeToken(DeriveKey("key1"))
	token2 := HandshakeToken(DeriveKey("key2"))

	if token1 == token2 {
		t.Fatal("different keys should produce different tokens")
	}
}

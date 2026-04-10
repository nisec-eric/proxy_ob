package internal

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"golang.org/x/crypto/chacha20poly1305"
	"io"
)

// Encrypt encrypts plaintext using ChaCha20-Poly1305 AEAD.
// The returned byte slice contains: nonce (12 bytes) + sealed data (ciphertext + 16-byte tag).
func Encrypt(key [32]byte, plaintext []byte) ([]byte, error) {
	aead, err := chacha20poly1305.New(key[:])
	if err != nil {
		return nil, fmt.Errorf("create AEAD cipher: %w", err)
	}

	var nonce [chacha20poly1305.NonceSize]byte
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}

	sealed := aead.Seal(nil, nonce[:], plaintext, nil)

	out := make([]byte, 0, len(nonce)+len(sealed))
	out = append(out, nonce[:]...)
	out = append(out, sealed...)
	return out, nil
}

// Decrypt decrypts data produced by Encrypt.
// Expects input format: nonce (12 bytes) + sealed data (ciphertext + 16-byte tag).
func Decrypt(key [32]byte, data []byte) ([]byte, error) {
	if len(data) < chacha20poly1305.NonceSize+chacha20poly1305.Overhead {
		return nil, fmt.Errorf("ciphertext too short: %d bytes", len(data))
	}

	aead, err := chacha20poly1305.New(key[:])
	if err != nil {
		return nil, fmt.Errorf("create AEAD cipher: %w", err)
	}

	nonce := data[:chacha20poly1305.NonceSize]
	sealed := data[chacha20poly1305.NonceSize:]

	plaintext, err := aead.Open(nil, nonce, sealed, nil)
	if err != nil {
		return nil, fmt.Errorf("decrypt: %w", err)
	}

	return plaintext, nil
}

// HandshakeToken computes a deterministic HMAC-SHA256 token from the key.
// Both client and server can derive the same token given the same key.
func HandshakeToken(key [32]byte) [32]byte {
	mac := hmac.New(sha256.New, key[:])
	mac.Write(key[:])

	var token [32]byte
	copy(token[:], mac.Sum(nil))
	return token
}

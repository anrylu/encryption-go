package aes

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"io"

	"github.com/xdg-go/pbkdf2"
)

const (
    saltSize = 16        // Salt size in bytes
    keySize  = 32        // AES-256 key size in bytes
    iterations = 10000   // Number of iterations for PBKDF2
)

func stringToAESKey(passphrase string, salt []byte) ([]byte, []byte, error) {
    // Generate a random salt if no provied
	if salt == nil {
		salt = make([]byte, saltSize)
		if _, err := io.ReadFull(rand.Reader, salt); err != nil {
			return nil, nil, err
		}
	}

    // Derive the AES key using PBKDF2
    key := pbkdf2.Key([]byte(passphrase), salt, iterations, keySize, sha256.New)

    return key, salt, nil
}

// EncryptMessage encrypts a message
func EncryptMessage(passphrase, msg string) (string, error) {
	// derive key
	key, salt, err := stringToAESKey(passphrase, nil)
    if err != nil {
        return "", err
    }

	// Create a new AES cipher block using the provided key
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	// Generate a random nonce (IV) for GCM mode
	nonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	// Create a new AES-GCM cipher with the generated nonce
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	// Encrypt the plaintext using AES-GCM
	ciphertext := aesgcm.Seal(nil, nonce, []byte(msg), nil)

	// Combine the nonce and ciphertext and encode them as base64
	result := base64.StdEncoding.EncodeToString(append(append(salt, nonce...), ciphertext...))

	return result, nil

}

// DecryptMessage encrypts a message
func DecryptMessage(passphrase, ciphertext string) (string, error) {
	// Decode the base64-encoded ciphertext and extract the nonce
	ct, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", err
	}
	salt := ct[:saltSize]
	nonce := ct[saltSize:saltSize+12]
	ct = ct[saltSize+12:]

	// derive key
	key, salt, err := stringToAESKey(passphrase, salt)
	if err != nil {
		return "", err
	}

	// Create a new AES cipher block using the provided key
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	// Create a new AES-GCM cipher with the provided nonce
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	// Decrypt the ciphertext using AES-GCM
	plaintext, err := aesgcm.Open(nil, nonce, ct, nil)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}

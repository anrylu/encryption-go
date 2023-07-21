package rsa

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
)

// GeneratreKeyPair generate rsa key pair
func GeneratreKeyPair() (string, string, error) {
	// generate RSA priate key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", "", err
	}

	// convert private key
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})

	// generate public key
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return "", "", err
	}

	// convert public key
	publicKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: publicKeyBytes,
	})

	return base64.StdEncoding.EncodeToString(privateKeyPEM),
		   base64.StdEncoding.EncodeToString(publicKeyPEM),
		   nil
}

func convertPublicKey(publicKeyEncoded string) (*rsa.PublicKey, error) {
	// Decode base64 encoded key
	decodedKey, err := base64.StdEncoding.DecodeString(publicKeyEncoded)
	if err != nil {
		return nil, err
	}

	// Parse PEM block
	block, _ := pem.Decode(decodedKey)
	if block == nil || block.Type != "RSA PUBLIC KEY" {
		return nil, err
	}

	// Parse RSA public key
	publicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	// Assert the public key type
	rsaPublicKey, ok := publicKey.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("assert public key type error")
	}

	return rsaPublicKey, nil
}

func convertPrivateKey(privateKeyEncoded string) (*rsa.PrivateKey, error) {
	// Decode base64 encoded key
	decodedKey, err := base64.StdEncoding.DecodeString(privateKeyEncoded)
	if err != nil {
		return nil, err
	}

	// Parse PEM block
	block, _ := pem.Decode(decodedKey)
	if block == nil || block.Type != "RSA PRIVATE KEY" {
		return nil, err
	}

	// Parse RSA pp=rivate key
	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	
	return privateKey, nil
}

// EncryptMessage encrypt message by public key
func EncryptMessage(publicKeyEncoded, msg string) (string, error) {
	// convert public key
	publicKey, err := convertPublicKey(publicKeyEncoded)
	if err != nil {
		return "", err
	}

	// Encrypt message using the public key
	msgEncrypted, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, publicKey, []byte(msg), nil)
	if err != nil {
		return "", nil
	}

	// base64 encode before return
	return base64.StdEncoding.EncodeToString(msgEncrypted), nil
}

// DecryptMessage decrypt message by private key
func DecryptMessage(privateKeyEncoded, ciphertext string) (string, error) {
	// convert private key
	privateKey, err := convertPrivateKey(privateKeyEncoded)
	if err != nil {
		return "", err
	}

	// Decode base64 encoded key
	msgEncrypted, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", err
	}

    // Decrypt the ciphertext using RSA-OAEP
    msg, err := rsa.DecryptOAEP(
		sha256.New(),
        rand.Reader,     // Random source for encryption
        privateKey,      // RSA private key
        msgEncrypted,    // Ciphertext to be decrypted
        nil,             // Optional label (set to nil if not used)
    )
    if err != nil {
        return "", err
    }

	return string(msg), nil
}

package eddsa

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
)

// GeneratreKeyPair generate eddsa key pair
func GeneratreKeyPair() (string, string, error) {
	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		return "", "", err
	}
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return "", "", err
	}
	privateKeyBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return "", "", err
	}
	publicKeyBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	}
	privateKeyBlock := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privateKeyBytes,
	}
	return base64.StdEncoding.EncodeToString(pem.EncodeToMemory(privateKeyBlock)),
		base64.StdEncoding.EncodeToString(pem.EncodeToMemory(publicKeyBlock)),
		nil
}

func convertPublicKey(publicKeyEncoded string) (ed25519.PublicKey, error) {
	keyPEM, err := base64.StdEncoding.DecodeString(publicKeyEncoded)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(keyPEM)
	keyBytes, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return keyBytes.(ed25519.PublicKey), nil
}

func convertPrivateKey(privateKeyEncoded string) (ed25519.PrivateKey, error) {
	keyPEM, err := base64.StdEncoding.DecodeString(privateKeyEncoded)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(keyPEM)
	keyBytes, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return keyBytes.(ed25519.PrivateKey), nil
}

// Sign sign the input message to generate a signature
func Sign(privateKeyEncoded, msg string) (string, error) {
	// convert private key
	privateKey, err := convertPrivateKey(privateKeyEncoded)
	if err != nil {
		return "", err
	}

	// sign message
	signature := ed25519.Sign(privateKey, []byte(msg))

	return base64.StdEncoding.EncodeToString(signature), nil
}

// Verify verify the message signature
func Verify(publicKeyEncoded, msg, signatureEncoded string) (bool, error) {
	// convert private key
	publicKey, err := convertPublicKey(publicKeyEncoded)
	if err != nil {
		return false, err
	}

	// decode signature
	signature, err := base64.StdEncoding.DecodeString(signatureEncoded)

	// verify signature
	isValid := ed25519.Verify(publicKey, []byte(msg), signature)

	return isValid, nil
}

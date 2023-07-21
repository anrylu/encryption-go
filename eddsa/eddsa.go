package eddsa

import (
	"crypto/ed25519"
	"encoding/base64"
)

// GeneratreKeyPair generate eddsa key pair
func GeneratreKeyPair() (string, string, error) {
	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		return "", "", err
	}
	return base64.StdEncoding.EncodeToString(privateKey), base64.StdEncoding.EncodeToString(publicKey), nil
}

func convertPublicKey(publicKeyEncoded string) (ed25519.PublicKey, error) {
	publicKeyBytes, err := base64.StdEncoding.DecodeString(publicKeyEncoded)
	if err != nil {
		return nil, err
	}

	return ed25519.PublicKey(publicKeyBytes), nil
}

func convertPrivateKey(privateKeyEncoded string) (ed25519.PrivateKey, error) {
	privateKeyBytes, err := base64.StdEncoding.DecodeString(privateKeyEncoded)
	if err != nil {
		return nil, err
	}
	return ed25519.PrivateKey(privateKeyBytes), nil
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

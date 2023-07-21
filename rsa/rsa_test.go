package rsa

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestEncryptDecrypt(t *testing.T) {
	msg := "this is a test message"

	// generate key
	privateKeyEncoded, publicKeyEncoded, err := GeneratreKeyPair()
	require.Equal(t, nil, err, "GeneratreKeyPair must return no error.")

	// encrypt
	ciphertext, err := EncryptMessage(publicKeyEncoded, msg)
	require.Equal(t, nil, err, "EncryptMessage must return no error.")

	// decrypt
	msgDecrypted, err := DecryptMessage(privateKeyEncoded, ciphertext)
	require.Equal(t, nil, err, "DecryptMessage must return no error.")

	// check msg
	require.Equal(t, msg, msgDecrypted, "Decrypted message must be the same.")
}

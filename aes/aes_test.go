package aes

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestEncryptDecrypt(t *testing.T) {
	passphrase := "this is a test key"
	msg := "this is a test message"

	// encrypt
	ciphertext, err := EncryptMessage(passphrase, msg)
	require.Equal(t, nil, err, "EncryptMessage must return no error.")

	// decrypt
	msgDecrypted, err := DecryptMessage(passphrase, ciphertext)
	require.Equal(t, nil, err, "DecryptMessage must return no error.")

	// check msg
	require.Equal(t, msg, msgDecrypted, "Decrypted message must be the same.")
}

package eddsa

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSignature(t *testing.T) {
	msg := "this is a test message"

	// get key pair
	privateKeyEncoded, publicKeyEncoded, err := GeneratreKeyPair()
	require.Equal(t, nil, err, "GeneratreKeyPair must return no error.")

	// sign
	signatureEncoded, err := Sign(privateKeyEncoded, msg)
	require.Equal(t, nil, err, "Sign must return no error.")

	// verify signature
	isValid, err := Verify(publicKeyEncoded, msg, signatureEncoded)
	require.Equal(t, nil, err, "DecryptMessage must return no error.")

	// check verify result
	require.Equal(t, true, isValid, "isValid must be true.")
}

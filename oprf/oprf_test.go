package oprf

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNegotiateWithNewKey(t *testing.T) {
	// client blind message
	// send to server
	finData, evalReqEncoded, err := Blind("this is my secret")
	require.Equal(t, nil, err, "BlindMessage must return no error.")
	require.NotEqual(t, nil, finData, "finData must not be nil.")
	require.NotEqual(t, "", evalReqEncoded, "evalReqEncoded must not be empty.")

	// server generate key
	keyEncoded, err := GenerateKey()
	require.Equal(t, nil, err, "GenerateKey must return no error.")
	require.NotEqual(t, "", keyEncoded, "keyEncoded must not be empty.")

	// server evaluate message
	// send back to client
	evaluatedElementBytesEncoded, err := BlindEvaluate(keyEncoded, evalReqEncoded)
	require.Equal(t, nil, err, "EvaluateMessage must return no error.")
	require.NotEqual(t, "", evaluatedElementBytesEncoded, "evaluatedElementBytesEncoded must not be empty.")

	// client finalize message
	finMsgEncoded, err := Finalize(finData, evaluatedElementBytesEncoded)
	require.Equal(t, nil, err, "FinalizeMessage must return no error.")
	require.NotEqual(t, "", finMsgEncoded, "evaluatedElementBytesEncoded must not be empty.")
}

func TestNegotiateWithOldKey(t *testing.T) {
	// client blind message
	// send to server
	finData, evalReqEncoded, err := Blind("this is my secret")
	require.Equal(t, nil, err, "BlindMessage must return no error.")
	require.NotEqual(t, nil, finData, "finData must not be nil.")
	require.NotEqual(t, "", evalReqEncoded, "evalReqEncoded must not be empty.")

	// server evaluate message
	// send back to client
	keyEncoded := "3Cpo/SxbB3iphZCMplkPBPJq9fM29S61wRZvJxwgIwM="
	evaluatedElementBytesEncoded, err := BlindEvaluate(keyEncoded, evalReqEncoded)
	require.Equal(t, nil, err, "EvaluateMessage must return no error.")
	require.NotEqual(t, "", evaluatedElementBytesEncoded, "evaluatedElementBytesEncoded must not be empty.")

	// client finalize message
	finMsgEncoded, err := Finalize(finData, evaluatedElementBytesEncoded)
	require.Equal(t, nil, err, "FinalizeMessage must return no error.")
	require.Equal(t, "4SbMyJR175bFjSLydlcV9jIHQp9pYUwkx2teiQtbiHxeP4HsOzAwjmmUEbYk4bak1v2BcNgix8/Fmhg3jfy8UQ==", finMsgEncoded, "evaluatedElementBytesEncoded is incorrecct.")
}
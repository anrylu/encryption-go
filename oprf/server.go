package oprf

import (
	"crypto/rand"
	"encoding/base64"

	"github.com/cloudflare/circl/group"
	"github.com/cloudflare/circl/oprf"
)

// GenerateKey generate the key to be used and return it in based64 encoded string
func GenerateKey() (string, error) {
	ret := ""

	// generate key
	key, err := oprf.GenerateKey(suiteToUse, rand.Reader)
	if err != nil {
		return ret, err
	}

	// marshal private key
	keyBytes, err := key.MarshalBinary()
	if err != nil {
		return ret, err
	}

	return base64.StdEncoding.EncodeToString(keyBytes), nil
}

func decodeKey(keyEncoded string) (*oprf.PrivateKey, error) {
	ret := &oprf.PrivateKey{}
	keyBytes, err := base64.StdEncoding.DecodeString(string(keyEncoded))
	if err != nil {
		return nil, err
	}
	err = ret.UnmarshalBinary(suiteToUse, keyBytes)
	return ret, err
}

// EvaluateMessage used at server side to evaluate the message and return the base64 encoded result
func BlindEvaluate(keyEncoded, evalReqEncoded string) (string, error) {
	// get private key
	private, err := decodeKey(keyEncoded)

    // decode input
    evalReqBytes, err := base64.StdEncoding.DecodeString(evalReqEncoded)
    if err != nil {
        return "", err
    }
    evalReqElements := make([]oprf.Blinded, 1)
    evalReqElements[0] = group.Ristretto255.NewElement()
    err = evalReqElements[0].UnmarshalBinary(evalReqBytes)
    if err != nil {
        return "", err
    }
    evalReq := &oprf.EvaluationRequest{
        Elements: evalReqElements,
    }

    // evalute
    server := oprf.NewServer(suiteToUse, private)
    evaluation, err := server.Evaluate(evalReq)
    if err != nil {
        return "", err
    }

    // encode element
    evaluatedElementBytes, err := evaluation.Elements[0].MarshalBinary()
    if err != nil {
        return "", err
    }
    evaluatedElementBytesEncoded := base64.StdEncoding.EncodeToString(evaluatedElementBytes)

    return evaluatedElementBytesEncoded, nil
}
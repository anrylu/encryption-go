package oprf

import (
	"encoding/base64"

	"github.com/cloudflare/circl/group"
	"github.com/cloudflare/circl/oprf"
)

var suiteToUse oprf.Suite = oprf.SuiteRistretto255

// Blind used at client side to blind the input message
func Blind(input string) (*oprf.FinalizeData, string, error) {
	client := oprf.NewClient(suiteToUse)

    // blind message
    finData, evalReq, err := client.Blind([][]byte{[]byte(input)})
    if err != nil {
        return nil, "", err
    }

    // marshal request
    evalReqBytes, err := evalReq.Elements[0].MarshalBinary()
    if err != nil {
        return nil, "", err
    }

    // base64 encode
    evalReqEncoded := base64.StdEncoding.EncodeToString(evalReqBytes)

    return finData, evalReqEncoded, nil
}

// Finalize used at client side to finalize the input message
func Finalize(finData *oprf.FinalizeData, evaluatedElementBytesEncoded string) (string, error) {
    client := oprf.NewClient(suiteToUse)

    // decode evaluatedElementBytesEncoded
    evaluatedElementBytes, err := base64.StdEncoding.DecodeString(evaluatedElementBytesEncoded)
    if err != nil {
        return "", err
    }
    evaluatedElements := make([]oprf.Evaluated, 1)
    evaluatedElements[0] = group.Ristretto255.NewElement()
    err = evaluatedElements[0].UnmarshalBinary(evaluatedElementBytes)
    if err != nil {
        return "", err
    }

    // create evaluation
    evaluation := &oprf.Evaluation{
        Elements: evaluatedElements,
    }

    // finalize
    outputs, err := client.Finalize(finData, evaluation)

    return base64.StdEncoding.EncodeToString(outputs[0]), err
}
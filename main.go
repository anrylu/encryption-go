package main

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/anrylu/encryption-go/oprf"
)

func help() {
	fmt.Printf("Usage: %s SUBCOMMAND [OPTIONS]", os.Args[0])
}

func readInput(msg string, reader *bufio.Reader) string {
	fmt.Printf(msg)
	data, _ := reader.ReadString('\n')
	return strings.Replace(data, "\n", "", -1)
}

func executeOPRF(reader *bufio.Reader, operation string, args []string) {
	switch operation {
	case "client":
		// blind message
		//msg := readInput("Please enter msg: ", reader)
		msg := "hello world"
		finData, evalReqEncoded, err := oprf.Blind(msg)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("evalReqEncoded: %s\n\n", evalReqEncoded)

		// finalize message
		evaluatedElementBytesEncoded := readInput("Please enter evaluatedElementBytesEncoded: ", reader)
		finMsgEncoded, err := oprf.Finalize(finData, evaluatedElementBytesEncoded)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("finMsgEncoded: %s\n", finMsgEncoded)

	case "server":
		// generate key
		keyEncoded := readInput("Please enter keyEncoded (leave empty to autogen): ", reader)
		if keyEncoded == "" {
			keyEncodedFromInput, err := oprf.GenerateKey()
			if err != nil {
				log.Fatal(err)
			}
			keyEncoded = keyEncodedFromInput
		}
		fmt.Printf("keyEncoded: %s\n", keyEncoded)

		// evaluate message
		evalReqEncoded := readInput("Please enter evalReqEncoded: ", reader)
		evaluatedElementBytesEncoded, err := oprf.BlindEvaluate(keyEncoded, evalReqEncoded)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("evaluatedElementBytesEncoded: %s\n", evaluatedElementBytesEncoded)
	}
}

func main() {
	reader := bufio.NewReader(os.Stdin)

	// check length
	if len(os.Args) <= 2 {
		help()
		return
	}

	// check subcommand
	switch os.Args[1] {
	case "oprf":
		executeOPRF(reader, os.Args[2], os.Args[3:])
	default:
		help()
	}
}

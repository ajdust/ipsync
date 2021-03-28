package main

import (
	"fmt"
	"github.com/ajdust/ipsync/pkg"
	"net/http"
	"os"
	"strings"
	"time"
)

func main() {
	if len(os.Args) != 3 {
		fmt.Println(`Two arguments required:
			[path to EC private key]
			[address of listener]`)
		return
	}

	privateKeyPath := os.Args[1]
	listenerAddr := os.Args[2]

	signer, err := pkg.CreateSignerFromPath(privateKeyPath)
	if err != nil {
		panic(err)
	}

	message, signature, err := signer.CreateTypicalSignature(time.Now().UTC())
	if err != nil {
		panic(err)
	}

	auth := fmt.Sprintf("%s%s", message, signature)
	req, err := http.NewRequest("GET", listenerAddr, strings.NewReader(""))
	if err != nil {
		panic(err)
	}

	req.Header.Set("Authentication", auth)
	_, err = http.DefaultClient.Do(req)
	if err != nil {
		panic(err)
	}
}

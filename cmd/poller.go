package main

import (
	"fmt"
	"github.com/ajdust/ipsync/pkg"
	"io/ioutil"
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

	message, signature, err := signer.CreateTimeSignature(time.Now().UTC())
	if err != nil {
		panic(err)
	}

	auth := fmt.Sprintf("%s%s", message, signature)
	req, err := http.NewRequest("GET", listenerAddr, strings.NewReader(""))
	if err != nil {
		panic(err)
	}

	req.Header.Set("Authentication", auth)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		panic(err)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}

	fmt.Printf("Response was %d: %s\n", resp.StatusCode, body)
}

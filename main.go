package main

import (
	"fmt"
	"github.com/ajdust/ipsync/auth"
	"io/ioutil"
	"net/http"
	"os"
	"os/exec"
	"strings"
)

var cachedRemoteAddrPath, currentRemoteAddr, updateConfigScriptPath string
var verifier auth.Verifier

func getCachedRemoteAddr() string {
	read, err := ioutil.ReadFile(cachedRemoteAddrPath)
	if err != nil {
		panic(err)
	}

	return string(read)
}

func setCachedRemoteAddr(content string) {
	err := ioutil.WriteFile(cachedRemoteAddrPath, []byte(content), 0)
	if err != nil {
		panic(err)
	}
}

func updateRemoteAddr(next string) {
	// remove port from ip:port formatted address
	previousIP := currentRemoteAddr[:strings.LastIndex(currentRemoteAddr, ":")]
	nextIP := next[:strings.LastIndex(next, ":")]
	_, err := exec.Command(updateConfigScriptPath, fmt.Sprintf("--old=%s", previousIP), fmt.Sprintf("--new=%s", nextIP)).Output()
	if err != nil {
		fmt.Printf("failed to run script: %s\n", err)
		return
	}

	setCachedRemoteAddr(next)
	currentRemoteAddr = next
}

func ping(w http.ResponseWriter, req *http.Request) {
	if !verifier.Verify(req) {
		w.WriteHeader(404)
		return
	}

	if req.RemoteAddr != currentRemoteAddr {
		updateRemoteAddr(req.RemoteAddr)
	}

	_, err := fmt.Fprintf(w, req.RemoteAddr)
	if err != nil {
		fmt.Printf("could not write response: %s\n", err)
	}
}

func main() {
	if len(os.Args) != 4 {
		fmt.Println(`Three arguments required:
			[path to config containing IP]
			[path to current IP in text file]
			[path to base64-encoded public key DER]`)
		return
	}

	cachedRemoteAddrPath = os.Args[1]
	if _, err := os.Stat(cachedRemoteAddrPath); os.IsNotExist(err) {
		fmt.Printf("Could not find file at '%s'\n", cachedRemoteAddrPath)
		return
	}

	updateConfigScriptPath = os.Args[2]
	if _, err := os.Stat(updateConfigScriptPath); os.IsNotExist(err) {
		fmt.Printf("Could not find file at '%s'\n", updateConfigScriptPath)
		return
	}

	pubKeyPath := os.Args[3]
	if _, err := os.Stat(pubKeyPath); os.IsNotExist(err) {
		fmt.Printf("Could not find file at '%s'\n", pubKeyPath)
		return
	}

	vfr, err := auth.CreateVerifierFromPath(pubKeyPath)
	if err != nil {
		fmt.Printf("Invalid public key path %s: %s", pubKeyPath, err)
		return
	}

	verifier = vfr
	currentRemoteAddr = getCachedRemoteAddr()

	http.HandleFunc("/ping", ping)
	err = http.ListenAndServe(":8090", nil)
	if err != nil {
		panic(err)
	}
}

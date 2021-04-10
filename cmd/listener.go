package main

import (
	"fmt"
	"github.com/ajdust/ipsync/pkg"
	"io/ioutil"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strings"
)

var cachedRemoteAddrPath, updateConfigScriptPath string
var verifier pkg.Verifier
var ipRegex = regexp.MustCompile(`^(?:[0-9]{1,3}\.){3}[0-9]{1,3}`)

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

func trimIP(s string) string {
	matches := ipRegex.FindAllString(strings.TrimSpace(s), -1)
	for _, v := range matches {
		return v
	}

	return ""
}

func updateConfig(previousIP, nextIP string) error {
	_, err := exec.Command(updateConfigScriptPath,
		fmt.Sprintf("--old=%s", previousIP),
		fmt.Sprintf("--new=%s", nextIP)).Output()
	if err != nil {
		return fmt.Errorf("failed to run script: %w", err)
	}

	return nil
}

func ping(w http.ResponseWriter, req *http.Request) {
	if !verifier.Verify(req) {
		w.WriteHeader(404)
		return
	}

	current := trimIP(getCachedRemoteAddr())
	next := trimIP(req.RemoteAddr)

	if current != next {
		err := updateConfig(current, next)
		if err != nil {
			w.WriteHeader(500)
			_, _ = fmt.Fprintf(w, fmt.Sprintf("%s", err))
			return
		}

		setCachedRemoteAddr(next)
	}

	_, err := fmt.Fprintf(w, req.RemoteAddr)
	if err != nil {
		fmt.Printf("could not write response: %s\n", err)
	}
}

func main() {
	if len(os.Args) != 5 {
		fmt.Println(`Three arguments required:
			[path to current IP in text file]
			[path to script to run when IP changes]
			[path to base64-encoded DER of EC public key]
			[address to listen on]`)
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

	vfr, err := pkg.CreateVerifierFromPath(pubKeyPath)
	if err != nil {
		fmt.Printf("Invalid public key path %s: %s", pubKeyPath, err)
		return
	}

	listenOn := os.Args[4]
	verifier = vfr

	http.HandleFunc("/ping", ping)
	err = http.ListenAndServe(listenOn, nil)
	if err != nil {
		panic(err)
	}
}

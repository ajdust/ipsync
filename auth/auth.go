package auth

import (
	"crypto/ecdsa"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io/ioutil"
	"math/big"
	"net/http"
	"time"
)

func hash(b []byte) []byte {
	h := sha512.New()
	h.Write(b)
	return h.Sum(nil)
}

// Validate a message signature with the given EC public key
func verifySignature(pubKey *ecdsa.PublicKey, message, b64sig string) error {
	// first decode the b64sig to extract the DER-encoded byte string
	der, err := base64.StdEncoding.DecodeString(b64sig)
	if err != nil {
		return fmt.Errorf("could not base64 decode signature %w", err)
	}

	// get R and S, compute the hash of our message, and verifySignature the signature
	r := big.NewInt(0).SetBytes(der[:len(der)/2])
	s := big.NewInt(0).SetBytes(der[len(der)/2:])
	h := hash([]byte(message))
	if !ecdsa.Verify(pubKey, h, r, s) {
		return errors.New("signature validation failed")
	}

	return nil
}

type Verifier struct {
	pubKey *ecdsa.PublicKey
}

func CreateVerifierFromPath(pubKeyPath string) (Verifier, error) {
	read, err := ioutil.ReadFile(pubKeyPath)
	if err != nil {
		panic(err)
	}

	decodePubKey, err := base64.StdEncoding.DecodeString(string(read))
	if err != nil {
		panic(err)
	}

	key, err := x509.ParsePKIXPublicKey(decodePubKey)
	if err != nil {
		panic(err)
	}

	pubKey := key.(*ecdsa.PublicKey)
	if pubKey == nil {
		return Verifier{}, errors.New("invalid public key")
	}

	return Verifier{pubKey}, nil
}

// Authenticate a request. The Authentication header is expected
// to contain the message and signature. The public key is shared beforehand.
// The message is the ISO8601 UTC datetime followed by 15 random characters.
func (verifier Verifier) Verify(req *http.Request) bool {
	authHeader := req.Header["Authentication"]
	if len(authHeader) != 1 {
		return false
	}

	auth := authHeader[0]
	if len(auth) < 150 || len(auth) > 300 {
		return false
	}

	date, err := time.Parse("20060102T150405", auth[:15])
	if err != nil {
		return false
	}

	// The datetime cannot be more than 10 minutes away from UTC now
	now := time.Now().UTC()
	if date.Before(now.Add(time.Duration(-10)*time.Minute)) ||
		date.After(now.Add(time.Duration(10)*time.Minute)) {
		return false
	}

	message := auth[:30]
	signature := auth[30:]
	if err := verifySignature(verifier.pubKey, message, signature); err != nil {
		return false
	}

	return true
}

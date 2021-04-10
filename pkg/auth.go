package pkg

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io/ioutil"
	"math/big"
	"net/http"
	"strings"
	"time"
	"unicode"
)

const messageSize = 50

// Remove all white space and returns from a string
func removeSpace(str string) string {
	var b strings.Builder
	b.Grow(len(str))
	for _, ch := range str {
		if !unicode.IsSpace(ch) {
			b.WriteRune(ch)
		}
	}
	return b.String()
}

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

// Verifier verifies ECDSA signatures with a public key
type Verifier struct {
	pubKey *ecdsa.PublicKey
}

func CreateVerifierFromPath(pubKeyPath string) (Verifier, error) {
	read, err := ioutil.ReadFile(pubKeyPath)
	if err != nil {
		return Verifier{}, err
	}

	content := string(read)
	content = strings.TrimSpace(content)
	content = strings.TrimPrefix(content, "-----BEGIN PUBLIC KEY-----")
	content = strings.TrimSuffix(content, "-----END PUBLIC KEY-----")
	content = removeSpace(content)

	decodePubKey, err := base64.StdEncoding.DecodeString(content)
	if err != nil {
		return Verifier{}, err
	}

	key, err := x509.ParsePKIXPublicKey(decodePubKey)
	if err != nil {
		return Verifier{}, err
	}

	pubKey := key.(*ecdsa.PublicKey)
	if pubKey == nil {
		return Verifier{}, errors.New("invalid public key")
	}

	return Verifier{pubKey}, nil
}

// Verify authenticates a request. The Authentication header is expected
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

	message := auth[:messageSize]
	signature := auth[messageSize:]
	if err := verifySignature(verifier.pubKey, message, signature); err != nil {
		return false
	}

	return true
}

type Signer struct {
	privateKey *ecdsa.PrivateKey
}

func CreateSignerFromPath(privKeyPath string) (Signer, error) {
	read, err := ioutil.ReadFile(privKeyPath)
	if err != nil {
		return Signer{}, err
	}

	content := string(read)
	content = strings.TrimSpace(content)
	content = strings.TrimPrefix(content, "-----BEGIN EC PRIVATE KEY-----")
	content = strings.TrimSuffix(content, "-----END EC PRIVATE KEY-----")
	content = removeSpace(content)

	decodePrivateKey, err := base64.StdEncoding.DecodeString(content)
	if err != nil {
		return Signer{}, err
	}

	privateKey, err := x509.ParseECPrivateKey(decodePrivateKey)
	if err != nil {
		return Signer{}, err
	}

	if privateKey == nil {
		return Signer{}, errors.New("invalid private key")
	}

	return Signer{privateKey}, nil
}

// Sign signs a string and returns a base64 encoded signature
func (signer Signer) Sign(message string) (string, error) {
	rdr := strings.NewReader(message)
	hashed := hash([]byte(message))
	r, s, err := ecdsa.Sign(rdr, signer.privateKey, hashed)
	if err != nil {
		return "", err
	}
	der := append(r.Bytes(), s.Bytes()...)
	return base64.StdEncoding.EncodeToString(der), nil
}

// generateRandomString returns a securely generated random string.
// It will return an error if the system's secure random
// number generator fails to function correctly, in which
// case the caller should not continue.
func generateRandomString(n int) (string, error) {
	const letters = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz-"
	ret := make([]byte, n)
	for i := 0; i < n; i++ {
		num, err := rand.Int(rand.Reader, big.NewInt(int64(len(letters))))
		if err != nil {
			return "", err
		}
		ret[i] = letters[num.Int64()]
	}

	return string(ret), nil
}

// CreateTimeSignature creates a message and signature with a datetime and random string
func (signer Signer) CreateTimeSignature(now time.Time) (string, string, error) {
	formatted := now.Format("20060102T150405")
	random, err := generateRandomString(messageSize - 15)
	if err != nil {
		return "", "", err
	}

	message := fmt.Sprintf("%s%s", formatted, random)
	messageRdr := strings.NewReader(message)
	hashed := hash([]byte(message))
	r, s, err := ecdsa.Sign(messageRdr, signer.privateKey, hashed)
	if err != nil {
		return "", "", fmt.Errorf("failed to CreateTimeSignature: %w", err)
	}

	der := append(r.Bytes(), s.Bytes()...)
	return message, base64.StdEncoding.EncodeToString(der), nil
}
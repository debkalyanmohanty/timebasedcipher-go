package cipher

import (
	"crypto/rand"
	"encoding/base64"
)

func generateNonce() (string, error) {

	b := make([]byte, 16)

	_, err := rand.Read(b)

	if err != nil {
		return "", err
	}

	return base64.RawURLEncoding.EncodeToString(b), nil
}

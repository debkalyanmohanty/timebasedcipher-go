package cipher

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

func Decrypt[T any](
	token string,
	secret string,
	intervalSeconds int64,
	opts *CipherOptions,
) (T, error) {
	var zero T

	parts := strings.Split(token, ".")

	if len(parts) != 3 || parts[0] != "v1" {
		return zero, errors.New("invalid token")
	}

	cipherBytes, err := B64Decode(parts[1])

	if err != nil {
		return zero, err
	}

	iv, err := B64Decode(parts[2])

	if err != nil {
		return zero, err
	}

	now := time.Now().Unix()

	timeSlot := now / intervalSeconds

	key, err := deriveKey(secret, timeSlot)

	if err != nil {
		return zero, err
	}

	block, err := aes.NewCipher(key)

	if err != nil {
		return zero, err
	}

	gcm, err := cipher.NewGCM(block)

	if err != nil {
		return zero, err
	}

	plain, err := gcm.Open(nil, iv, cipherBytes, nil)

	if err != nil {
		return zero, err
	}

	var payload TokenPayload[T]

	json.Unmarshal(plain, &payload)

	if err := checkReplay(payload.Nonce); err != nil {
		return zero, err
	}

	return payload.Data, nil
}

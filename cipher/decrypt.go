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

	if opts == nil {
		opts = &CipherOptions{}
	}

	parts := strings.SplitN(token, ".", 3)

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

	tolerance := opts.ClockToleranceSeconds
	if tolerance == 0 {
		tolerance = 30
	}

	slots := []int64{
		now / intervalSeconds,
		(now - tolerance) / intervalSeconds,
		(now + tolerance) / intervalSeconds,
	}

	var plain []byte

	for _, slot := range slots {

		key, err := deriveKey(secret, slot)
		if err != nil {
			continue
		}

		block, err := aes.NewCipher(key)
		if err != nil {
			continue
		}

		gcm, err := cipher.NewGCM(block)
		if err != nil {
			continue
		}

		plain, err = gcm.Open(nil, iv, cipherBytes, nil)
		if err == nil {
			break
		}
	}

	if plain == nil {
		return zero, errors.New("unable to decrypt token")
	}

	var payload TokenPayload[T]

	if err := json.Unmarshal(plain, &payload); err != nil {
		return zero, err
	}

	expectedSig := opts.Signature
	if expectedSig == "" {
		expectedSig = "default-signature"
	}

	if payload.Sig != expectedSig {
		return zero, errors.New("invalid signature")
	}

	if payload.Exp+tolerance < now {
		return zero, errors.New("token expired")
	}

	if err := checkReplay(payload.Nonce); err != nil {
		return zero, err
	}

	return payload.Data, nil
}

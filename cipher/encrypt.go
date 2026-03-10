package cipher

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"time"
)

func Encrypt[T any](
	data T,
	secret string,
	intervalSeconds int64,
	opts *CipherOptions,
) (string, error) {

	if opts == nil {
		opts = &CipherOptions{}
	}

	now := time.Now().Unix()

	ttl := opts.TTLSeconds
	if ttl == 0 {
		ttl = intervalSeconds
	}

	signature := opts.Signature
	if signature == "" {
		signature = "default-signature"
	}

	nonce, err := generateNonce()
	if err != nil {
		return "", err
	}

	payload := TokenPayload[T]{
		Sig:   signature,
		Iat:   now,
		Exp:   now + ttl,
		Nonce: nonce,
		Data:  data,
	}

	timeSlot := now / intervalSeconds

	key, err := deriveKey(secret, timeSlot)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	iv := make([]byte, 12)
	rand.Read(iv)

	jsonData, _ := json.Marshal(payload)

	cipherText := gcm.Seal(nil, iv, jsonData, nil)

	token := "v1." +
		base64.RawURLEncoding.EncodeToString(cipherText) +
		"." +
		base64.RawURLEncoding.EncodeToString(iv)

	return token, nil
}

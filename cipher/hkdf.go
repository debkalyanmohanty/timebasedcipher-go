package cipher

import (
	"crypto/sha256"
	"io"
	"strconv"

	"golang.org/x/crypto/hkdf"
)

func deriveKey(secret string, timeSlot int64) ([]byte, error) {

	salt := []byte(strconv.FormatInt(timeSlot, 10))
	info := []byte("time-based-encryption")

	h := hkdf.New(
		sha256.New,
		[]byte(secret),
		salt,
		info,
	)

	key := make([]byte, 32)

	if _, err := io.ReadFull(h, key); err != nil {
		return nil, err
	}

	return key, nil
}

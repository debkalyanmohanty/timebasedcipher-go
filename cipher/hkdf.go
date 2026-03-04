package cipher

import (
	"crypto/sha256"
	"io"

	"golang.org/x/crypto/hkdf"
)

func deriveKey(secret string, timeSlot int64) ([]byte, error) {

	h := hkdf.New(
		sha256.New,
		[]byte(secret),
		[]byte(string(rune(timeSlot))),
		[]byte("time-based-encryption"),
	)

	key := make([]byte, 32)
	_, err := io.ReadFull(h, key)

	return key, err
}

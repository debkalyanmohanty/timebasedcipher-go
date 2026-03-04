package cipher

import "encoding/base64"

func B64Encode(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

func B64Decode(data string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(data)
}

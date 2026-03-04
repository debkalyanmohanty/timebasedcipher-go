package cipher

type CipherOptions struct {
	TTLSeconds            int64
	ClockToleranceSeconds int64
	Signature             string
}

type TokenPayload[T any] struct {
	Sig   string `json:"sig"`
	Iat   int64  `json:"iat"`
	Exp   int64  `json:"exp"`
	Nonce string `json:"nonce"`
	Data  T      `json:"data"`
}

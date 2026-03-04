package cipher

import (
	"errors"
	"sync"
)

var nonceStore sync.Map

func checkReplay(nonce string) error {

	if _, exists := nonceStore.Load(nonce); exists {
		return errors.New("replay attack detected")
	}

	nonceStore.Store(nonce, struct{}{})

	return nil
}

package cache

import "sync"

type KeyCache struct {
	store sync.Map
}

func (k *KeyCache) Get(key string) ([]byte, bool) {
	val, ok := k.store.Load(key)

	if !ok {
		return nil, false
	}

	return val.([]byte), true
}

func (k *KeyCache) Set(key string, value []byte) {
	k.store.Store(key, value)
}

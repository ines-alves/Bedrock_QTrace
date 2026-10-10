package fixtures

import (
	"crypto/rand"
	"crypto/subtle"
)

func salt() []byte {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b
}

func same(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}

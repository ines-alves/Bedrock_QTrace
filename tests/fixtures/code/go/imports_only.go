package fixtures

import (
	h1 "crypto/sha1"
	"crypto/sha256"
)

func legacy() {
	_ = h1.New()
	_ = sha256.Size
}

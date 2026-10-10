package fixtures

import (
	"crypto/pbkdf2"
	"crypto/sha512"
)

func deriveStd(password string, salt []byte) ([]byte, error) {
	return pbkdf2.Key(sha512.New, password, salt, 210000, 64)
}

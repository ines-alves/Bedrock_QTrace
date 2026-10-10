package main

import (
	"crypto/pbkdf2"
	"crypto/sha256"
)

func stdlib(password string, salt []byte) ([]byte, error) {
	return pbkdf2.Key(sha256.New, password, salt, 600000, 32)
}

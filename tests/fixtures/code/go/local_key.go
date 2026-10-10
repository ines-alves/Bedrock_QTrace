package main

import (
	"crypto/aes"
	"crypto/rand"
)

func localKey() {
	key := []byte("0123456789abcdef")
	block, _ := aes.NewCipher(key)
	_ = block
}

func localKey256() {
	var key = []byte("0123456789abcdef0123456789abcdef")
	block, _ := aes.NewCipher(key)
	_ = block
}

func sink(key []byte) {
	block, _ := aes.NewCipher(key)
	_ = block
}

func caller() {
	secret := []byte("fedcba9876543210")
	sink(secret)
}

func reassigned(other []byte) {
	key := []byte("0123456789abcdef")
	key = other
	block, _ := aes.NewCipher(key)
	_ = block
}

func generated() {
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	block, _ := aes.NewCipher(key)
	_ = block
}

func literalIsPlaintext() {
	key := make([]byte, 16)
	_, _ = rand.Read(key)
	payload := []byte("4111-1111-1111-1111")
	block, _ := aes.NewCipher(key)
	block.Encrypt(payload, payload)
}

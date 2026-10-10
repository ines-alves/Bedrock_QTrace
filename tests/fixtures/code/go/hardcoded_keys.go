package main

import (
	"crypto/aes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
)

var constKey = []byte("0123456789ABCDEF")
var hopKey = []byte("hop-key-0123456789")
var macKey = []byte("shared-signing-key-32-bytes-long")
var salt = []byte("fixed-salt-value")

func fromConstant() {
	block, _ := aes.NewCipher(constKey)
	_ = block
}

func inline() {
	block, _ := aes.NewCipher([]byte("fedcba9876543210"))
	_ = block
}

func withKey(key []byte) {
	block, _ := aes.NewCipher(key)
	_ = block
}

func throughCallSite() {
	withKey(hopKey)
}

func macTag(data []byte) []byte {
	m := hmac.New(sha256.New, macKey)
	m.Write(data)
	return m.Sum(nil)
}

func saltedDigest(data []byte) [32]byte {
	return sha256.Sum256(append(salt, data...))
}

func randomKey() {
	key := make([]byte, 32)
	rand.Read(key)
	block, _ := aes.NewCipher(key)
	_ = block
}

func importedKey() {
	key, _ := loadKey()
	block, _ := aes.NewCipher(key)
	_ = block
}

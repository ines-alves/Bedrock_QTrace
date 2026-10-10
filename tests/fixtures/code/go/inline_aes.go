package main

import (
	"crypto/aes"
	"crypto/cipher"
)

var constKey = []byte("fedcba9876543210")

func gcm128() {
	block, _ := aes.NewCipher([]byte("0123456789abcdef"))
	gcm, _ := cipher.NewGCM(block)
	_ = gcm
}

func raw256() {
	block, _ := aes.NewCipher([]byte(`0123456789abcdef0123456789abcdef`))
	_ = block
}

func ecb(src, dst []byte) {
	block, _ := aes.NewCipher([]byte("0123456789abcdef"))
	for i := 0; i < len(src); i += 16 {
		block.Encrypt(dst[i:], src[i:])
	}
}

func fromConstant() {
	block, _ := aes.NewCipher(constKey)
	_ = block
}

func imported(key []byte) {
	block, _ := aes.NewCipher(key)
	_ = block
}

package fixtures

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
)

const keyLen = 32

var fixedKey = []byte("0123456789ABCDEF")

func newKey() []byte {
	key := make([]byte, keyLen)
	rand.Read(key)
	return key
}

func sealGCM(key, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

func encryptBlocks(key, padded []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	out := make([]byte, len(padded))
	for i := 0; i < len(padded); i += aes.BlockSize {
		block.Encrypt(out[i:i+aes.BlockSize], padded[i:i+aes.BlockSize])
	}
	return out, nil
}

func encryptChained(key, padded, iv []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	out := make([]byte, len(padded))
	prev := iv
	for i := 0; i < len(padded); i += aes.BlockSize {
		for j := 0; j < aes.BlockSize; j++ {
			out[i+j] = padded[i+j] ^ prev[j]
		}
		block.Encrypt(out[i:i+aes.BlockSize], out[i:i+aes.BlockSize])
		prev = out[i : i+aes.BlockSize]
	}
	return out, nil
}

func encryptCBC(key, padded, iv []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	out := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(out, padded)
	return out, nil
}

func encryptOne(key, one []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	out := make([]byte, aes.BlockSize)
	block.Encrypt(out, one)
	return out, nil
}

func streamCTR(key, iv, data []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	out := make([]byte, len(data))
	cipher.NewCTR(block, iv).XORKeyStream(out, data)
	return out, nil
}

func usePooled(data []byte) ([]byte, error) {
	key := newKey()
	return sealGCM(key, data)
}

func useFixed(data []byte) ([]byte, error) {
	return encryptBlocks(fixedKey, data)
}

func useImported(key, data []byte) ([]byte, error) {
	return encryptOne(key, data)
}

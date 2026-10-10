package fixtures

import (
	"crypto/des"
	"crypto/rc4"
)

func desCipher(key []byte) {
	_, _ = des.NewCipher(key)
}

func tripleDES(key []byte) {
	_, _ = des.NewTripleDESCipher(key)
}

func stream(key []byte) {
	_, _ = rc4.NewCipher(key)
}

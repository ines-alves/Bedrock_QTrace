package fixtures

import (
	"crypto"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
)

func md5Sum(data []byte) [16]byte {
	return md5.Sum(data)
}

func sha1Sum(data []byte) [20]byte {
	return sha1.Sum(data)
}

func sha1Stream() {
	h := sha1.New()
	_ = h
}

func sha256Sum(data []byte) [32]byte {
	return sha256.Sum256(data)
}

func sha224Sum(data []byte) [28]byte {
	return sha256.Sum224(data)
}

func sha384Sum(data []byte) [48]byte {
	return sha512.Sum384(data)
}

func sha512Sum(data []byte) [64]byte {
	return sha512.Sum512(data)
}

func digestName() crypto.Hash {
	return crypto.SHA1
}

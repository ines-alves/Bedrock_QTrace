package fixtures

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"

	"golang.org/x/crypto/pbkdf2"
)

func macSHA256(key, data []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)
}

func macSHA1(key, data []byte) []byte {
	h := hmac.New(sha1.New, key)
	h.Write(data)
	return h.Sum(nil)
}

func macSHA384(key, data []byte) []byte {
	h := hmac.New(sha512.New384, key)
	h.Write(data)
	return h.Sum(nil)
}

func macPerChunk(key []byte, chunks [][]byte) [][]byte {
	var tags [][]byte
	for _, chunk := range chunks {
		h := hmac.New(sha256.New, key)
		h.Write(chunk)
		tags = append(tags, h.Sum(nil))
	}
	return tags
}

func derive(password, salt []byte) []byte {
	return pbkdf2.Key(password, salt, 600000, 32, sha256.New)
}

func deriveRolled(password, salt []byte, iter int) []byte {
	var index [4]byte
	binary.BigEndian.PutUint32(index[:], 1)
	mac := hmac.New(sha256.New, password)
	mac.Write(salt)
	mac.Write(index[:])
	u := mac.Sum(nil)
	t := make([]byte, len(u))
	copy(t, u)
	for i := 1; i < iter; i++ {
		mac := hmac.New(sha256.New, password)
		mac.Write(u)
		u = mac.Sum(nil)
		for j := range t {
			t[j] ^= u[j]
		}
	}
	return t
}

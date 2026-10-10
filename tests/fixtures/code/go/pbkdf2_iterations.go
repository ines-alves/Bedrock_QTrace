package main

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"

	"golang.org/x/crypto/pbkdf2"
)

const rounds = 210_000

func literal(password, salt []byte) []byte {
	return pbkdf2.Key(password, salt, 4096, 32, sha1.New)
}

func constant(password, salt []byte) []byte {
	return pbkdf2.Key(password, salt, rounds, 32, sha256.New)
}

func computed(password, salt []byte) []byte {
	n := len(salt) * 1000
	return pbkdf2.Key(password, salt, n, 32, sha256.New)
}

func viaParameter(password, salt []byte, iter int) []byte {
	return pbkdf2.Key(password, salt, iter, 32, sha256.New)
}

func caller(password, salt []byte) []byte {
	return viaParameter(password, salt, 100000)
}

func handRolled(password, salt []byte, iter int) []byte {
	mac := hmac.New(sha256.New, password)
	mac.Write(salt)
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

func handRolledCaller(password, salt []byte) []byte {
	return handRolled(password, salt, 10000)
}

func handRolledFixed(password, salt []byte) []byte {
	mac := hmac.New(sha256.New, password)
	mac.Write(salt)
	u := mac.Sum(nil)
	t := make([]byte, len(u))
	copy(t, u)
	for i := 1; i < 5000; i++ {
		mac := hmac.New(sha256.New, password)
		mac.Write(u)
		u = mac.Sum(nil)
		for j := range t {
			t[j] ^= u[j]
		}
	}
	return t
}

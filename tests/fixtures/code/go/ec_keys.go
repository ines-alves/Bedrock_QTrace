package fixtures

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"

	"golang.org/x/crypto/curve25519"
)

func signingKey() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

func strongSigningKey() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
}

func variableCurve(c elliptic.Curve) (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(c, rand.Reader)
}

func sign(priv *ecdsa.PrivateKey, digest []byte) ([]byte, error) {
	return ecdsa.SignASN1(rand.Reader, priv, digest)
}

func verify(pub *ecdsa.PublicKey, digest, sig []byte) bool {
	return ecdsa.VerifyASN1(pub, digest, sig)
}

func agreeP256() (*ecdh.PrivateKey, error) {
	return ecdh.P256().GenerateKey(rand.Reader)
}

func agreeX25519() (*ecdh.PrivateKey, error) {
	return ecdh.X25519().GenerateKey(rand.Reader)
}

func legacyX25519(priv, peer []byte) ([]byte, error) {
	return curve25519.X25519(priv, peer)
}

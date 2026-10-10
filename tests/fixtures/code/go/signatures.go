package fixtures

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
)

const rsaBits = 3072

func newKey() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, 2048)
}

func newBigKey() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, rsaBits)
}

func signLinked(key *rsa.PrivateKey, digest []byte) ([]byte, error) {
	return rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest)
}

func verifyLinked(pub *rsa.PublicKey, digest, sig []byte) error {
	return rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest, sig)
}

func signPSS(key *rsa.PrivateKey, digest []byte) ([]byte, error) {
	return rsa.SignPSS(rand.Reader, key, crypto.SHA256, digest, nil)
}

func run(digest []byte) error {
	key, err := newKey()
	if err != nil {
		return err
	}
	sig, err := signLinked(key, digest)
	if err != nil {
		return err
	}
	if err := verifyLinked(&key.PublicKey, digest, sig); err != nil {
		return err
	}
	_, err = signPSS(key, digest)
	return err
}

func signImported(imported *rsa.PrivateKey, digest []byte) ([]byte, error) {
	return rsa.SignPKCS1v15(rand.Reader, imported, crypto.SHA256, digest)
}

func edKeys() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	return ed25519.GenerateKey(rand.Reader)
}

func edSign(priv ed25519.PrivateKey, msg []byte) []byte {
	return ed25519.Sign(priv, msg)
}

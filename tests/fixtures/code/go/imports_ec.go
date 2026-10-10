package fixtures

import (
	ec "crypto/ecdsa"
	"crypto/ecdh"
	"crypto/mlkem"

	"golang.org/x/crypto/curve25519"
)

var (
	_ *ec.PrivateKey
	_ ecdh.Curve
	_ *mlkem.DecapsulationKey768
	_ = curve25519.PointSize
)

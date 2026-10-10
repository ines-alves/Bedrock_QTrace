package fixtures

import "crypto/mlkem"

func newKEM768() (*mlkem.DecapsulationKey768, error) {
	return mlkem.GenerateKey768()
}

func newKEM1024() (*mlkem.DecapsulationKey1024, error) {
	return mlkem.GenerateKey1024()
}

func peer768(raw []byte) (*mlkem.EncapsulationKey768, error) {
	return mlkem.NewEncapsulationKey768(raw)
}

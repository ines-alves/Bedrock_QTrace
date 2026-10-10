package fixtures

import (
	"crypto/tls"
)

func insecureClient() *tls.Config {
	return &tls.Config{InsecureSkipVerify: true}
}

func insecureAssigned() *tls.Config {
	cfg := &tls.Config{}
	cfg.InsecureSkipVerify = true
	return cfg
}

func verified() *tls.Config {
	return &tls.Config{InsecureSkipVerify: false}
}

func fromFlag(skip bool) *tls.Config {
	return &tls.Config{InsecureSkipVerify: skip}
}

func isInsecure(cfg *tls.Config) bool {
	return cfg.InsecureSkipVerify == true
}

package fixtures

import (
	"crypto/tls"
)

func legacyClient() *tls.Config {
	return &tls.Config{MinVersion: tls.VersionTLS10}
}

func legacyServer() *tls.Config {
	cfg := &tls.Config{}
	cfg.MinVersion = tls.VersionTLS11
	cfg.MaxVersion = tls.VersionSSL30
	return cfg
}

func modern() *tls.Config {
	return &tls.Config{MinVersion: tls.VersionTLS12}
}

func describe(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return "TLS 1.0"
	}
	if version == tls.VersionTLS11 {
		return "TLS 1.1"
	}
	return "unknown"
}

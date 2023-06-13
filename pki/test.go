package pki

import (
	"crypto/x509"
	"testing"
	"time"
)

// TestDenylistWithCert sets a new Denylist on the Validator and adds the certificate.
// This is useful in integrations tests etc.
func TestDenylistWithCert(t *testing.T, val Validator, cert *x509.Certificate) {
	dl := &denylistImpl{
		url:         "some-url",
		lastUpdated: time.Now(),
	}
	dl.entries.Store(&[]denylistEntry{
		{
			Issuer:        cert.Issuer.String(),
			SerialNumber:  cert.SerialNumber.String(),
			JWKThumbprint: certKeyJWKThumbprint(cert),
			Reason:        `testing purposes`,
		},
	})
	switch v := val.(type) {
	case *PKI:
		v.denylist = dl
	case *validator:
		v.denylist = dl
	default:
		t.Fatal("cannot set Denylist on val")
	}
}

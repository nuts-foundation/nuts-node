/*
 * Copyright (C) 2023 Nuts community
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 *
 */

package pki

import (
	"crypto/x509"
	"testing"
)

// TestConfig is the same as DefaultConfig without a denylist URL set.
func TestConfig(t *testing.T) Config {
	return Config{
		Denylist:           DenylistConfig{},
		MaxUpdateFailHours: 4,
		Softfail:           true,
	}
}

// SetNewDenylistWithCert sets a new Denylist on the Validator and adds the certificate.
// This is useful in integrations tests etc.
func SetNewDenylistWithCert(t *testing.T, val Validator, cert *x509.Certificate) {
	dl := &denylistImpl{
		url: "some-url",
	}
	now := nowFunc()
	dl.lastUpdated.Store(&now)
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

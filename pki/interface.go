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
	"crypto/tls"
	"crypto/x509"
	"errors"
	"github.com/nuts-foundation/nuts-node/core"
)

// errors
var (
	ErrCRLMissing    = errors.New("crl is missing")
	ErrCRLExpired    = errors.New("crl has expired")
	ErrCertRevoked   = errors.New("certificate is revoked")
	ErrCertUntrusted = errors.New("certificate's issuer is not trusted")
)

type Validator interface {
	// Validate returns an error if any of the certificates in the chain has been revoked, or if the request cannot be processed.
	// ErrCertRevoked and ErrCertUntrusted indicate that at least one of the certificates is revoked, or signed by a CA that is not in the truststore.
	// ErrCRLMissing and ErrCRLExpired signal that at least one of the certificates cannot be validated reliably.
	// If the certificate was revoked on an expired CRL, it wil return ErrCertRevoked.
	// Ignoring all errors except ErrCertRevoked changes the behavior from hard-fail to soft-fail. Without a truststore, the Validator is a noop if set to soft-fail
	// The certificate chain is expected to be sorted leaf to root.
	Validate(chain []*x509.Certificate) error

	// SetVerifyPeerCertificateFunc sets config.ValidatePeerCertificate to use Validate.
	SetVerifyPeerCertificateFunc(config *tls.Config) error

	// AddTruststore adds all CAs to the truststore for validation of CRL signatures. It also adds all CRL Distribution Endpoints found in the chain.
	// CRL Distribution Points encountered during operation, such as on end user certificates, are only added to the monitored CRLs if their issuer is in the truststore.
	AddTruststore(chain []*x509.Certificate) error
}

// Provider is an interface for providing PKI services (e.g. TLS configuration, certificate validation).
type Provider interface {
	Validator
	// CreateTLSConfig creates a tls.Config for outbound connections. It returns nil (and no error) if TLS is disabled.
	CreateTLSConfig(cfg core.TLSConfig) (*tls.Config, error)
}

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
	"time"
)

// errors
var (
	ErrCRLMissing    = errors.New("crl is missing")
	ErrCRLExpired    = errors.New("crl has expired")
	ErrCertRevoked   = errors.New("certificate is revoked")
	ErrUnknownIssuer = errors.New("unknown certificate issuer")
	// ErrDenylistMissing occurs when the denylist cannot be downloaded
	ErrDenylistMissing = errors.New("denylist cannot be retrieved")

	// ErrCertBanned means the certificate was banned by a denylist rather than revoked by a CRL
	ErrCertBanned = errors.New("certificate is banned")
)

// Denylist implements a global certificate rejection
type Denylist interface {
	// LastUpdated provides the time at which the denylist was last retrieved
	LastUpdated() time.Time

	// Update fetches a new copy of the denylist
	Update() error

	// URL returns the URL of the denylist
	URL() string

	// ValidateCert returns an error if a certificate should not be used
	ValidateCert(cert *x509.Certificate) error

	// Subscribe registers a callback that is triggered everytime the denylist is updated
	Subscribe(f func())
}

// Validator is used to check the revocation status of certificates on the issuer controlled CRL and the user controlled Denylist.
// It does NOT manage trust and assumes all presented certificates belong to a trusted certificate tree.
type Validator interface {
	// CheckCRL returns an error if any of the certificates in the chain has been revoked, or if the request cannot be processed.
	// All certificates in the chain are considered trusted, which means that the caller has verified the integrity of the chain and appropriateness for the use-case.
	// Any new CA / CRL in the chain will be added to the internal watchlist and updated periodically, so it MUST NOT be called on untrusted/invalid chains.
	// The certificate chain MUST be sorted leaf to root.
	//
	// ErrCertRevoked and ErrUnknownIssuer indicate that at least one of the certificates is revoked, or signed by an unknown CA (so we have no key to verify the CRL).
	// ErrCRLMissing and ErrCRLExpired signal that at least one of the certificates cannot be validated reliably.
	// If the certificate was revoked on an expired CRL, it wil return ErrCertRevoked.
	//
	// CheckCRL uses the configured soft-/hard-fail strategy
	// If set to soft-fail it ignores ErrCRLMissing and ErrCRLExpired errors.
	CheckCRL(chain []*x509.Certificate) error

	// CheckCRLStrict does the same as CheckCRL, except it always uses the hard-fail strategy.
	CheckCRLStrict(chain []*x509.Certificate) error

	// SetVerifyPeerCertificateFunc sets config.ValidatePeerCertificate to use CheckCRL.
	SetVerifyPeerCertificateFunc(config *tls.Config) error

	// SubscribeDenied registers a callback that is triggered everytime the denylist is updated.
	// This can be used to revalidate all certificates on long-lasting connections by calling CheckCRL on them again.
	SubscribeDenied(f func())
}

// Provider is an interface for providing PKI services (e.g. TLS configuration, certificate validation).
type Provider interface {
	Validator
	// CreateTLSConfig creates a tls.Config from the core.TLSConfig for outbound connections.
	// It returns (nil, nil)  if core.TLSConfig.Enabled() == false.
	CreateTLSConfig(cfg core.TLSConfig) (*tls.Config, error)
}

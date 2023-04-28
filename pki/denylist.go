/*
 * Nuts node
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
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync/atomic"
	"time"

	config "github.com/nuts-foundation/nuts-node/pki/config"

	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jws"
)

var (
	// ErrDenylistMissing occurs when the denylist cannot be downloaded
	ErrDenylistMissing = errors.New("denylist cannot be retrieved")

	// ErrCertBanned means the certificate was banned by a denylist rather than revoked by a CRL
	ErrCertBanned = errors.New("certificate is banned")
)

type Denylist interface {
	LastUpdated() time.Time
	Update() error
	URL() string
	ValidateCert(cert *x509.Certificate) error
}

// denylistImpl implements arbitrary certificate rejection using issuer and serial number tuples
type denylistImpl struct {
	// url specifies the URL where the denylist is downloaded
	url string

	// entries is the decoded entries from the downloaded denylist
	entries atomic.Pointer[[]denylistEntry]

	// trustedKey is an Ed25519 key which must sign the denylist
	trustedKey jwk.Key

	// lastUpdated contains the time the certificate was last updated
	lastUpdated time.Time
}

// denylistEntry contains parameters for an X.509 certificate that must not be accepted for TLS connections
type denylistEntry struct {
	// Issuer is a string representation (x509.Certificate.Issuer.String()) of the certificate
	Issuer string

	// SerialNumber is a string representation (x509.Certificate.SerialNumber.String()) of the certificate
	SerialNumber string

	// JWKThumbprint is an identifier of the public key per https://www.rfc-editor.org/rfc/rfc7638
	JWKThumbprint string

	Reason string
}

// New creates a denylist with the specified configuration
func New(config config.DenylistConfig) (Denylist, error) {
	// "Disable" (operate in a NOP mode) the denylist when the URL is empty
	if config.URL == "" {
		// Return the new denylist and a nil error
		return &denylistImpl{
			trustedKey: nil,
			url:        "",
		}, nil
	}

	// Parse the trusted key
	key, err := jwk.ParseKey([]byte(config.TrustedSigner), jwk.WithPEM(true))
	if err != nil {
		return nil, fmt.Errorf("failed to parse key: %w", err)
	}

	// Return the new denylist and a nil error
	return &denylistImpl{
		trustedKey: key,
		url:        config.URL,
	}, nil
}

// ValidateCert checks for the issuer and serialNumber in the denylist, returning nil when the cert is permitted
// or an error when the cert is denylisted or the denylist cannot be retrieved
func (b *denylistImpl) ValidateCert(cert *x509.Certificate) error {
	// Denylists with an empty URL are a NOP
	if b.URL() == "" {
		return nil
	}

	// Extract the necessary information from the certificate in order to process the denylist entry
	issuer := cert.Issuer.String()
	serialNumber := cert.SerialNumber.String()
	thumbprint := certKeyJWKThumbprint(cert)

	// If the denylist has not yet been downloaded, do so now
	if b.lastUpdated.IsZero() {
		// Trigger an update of the denylist
		if err := b.Update(); err != nil {
			// If the denylist download failed then log a message about it
			logger().WithError(err).
				WithField("Issuer", issuer).
				WithField("S/N", serialNumber).
				Error("cert validation failed because the denylist cannot be downloaded")

			// Return an error indicating the denylist cannot be retrieved
			return ErrDenylistMissing
		}
	}

	// Fetch the entries
	entriesPtr := b.entries.Load()

	// The entries pointer should not be empty because of the lastUpdated check above
	if entriesPtr == nil {
		// If the entries still cannot be fetched then something is not right so return an error
		return ErrDenylistMissing
	}

	// Check each entry in the denylist for matches
	for _, entry := range *entriesPtr {
		// Check for this issuer and serial number combination
		if entry.Issuer == issuer && entry.SerialNumber == serialNumber && entry.JWKThumbprint == thumbprint {
			// Return an error indicating the certificate has been denylisted
			return fmt.Errorf("%w: %s", ErrCertBanned, entry.Reason)
		}
	}

	// Return a nil error as the certificate hasn't been denylisted
	return nil
}

func (b *denylistImpl) LastUpdated() time.Time {
	return b.lastUpdated
}

func (b *denylistImpl) URL() string {
	return b.url
}

// update downloads the denylist, and updates the in-memory representation
func (b *denylistImpl) Update() error {
	// Updating a denylist with a URL is a NOP
	if b.URL() == "" {
		return nil
	}

	// Download the denylist
	bytes, err := b.download()
	if err != nil {
		logger().WithError(err).
			WithField("URl", b.url).
			Warn("certiciate denylist cannot be downloaded")
		return err
	}

	// Check the signature of the denylist
	payload, err := jws.Verify(bytes, jwa.EdDSA, b.trustedKey)
	if err != nil {
		return fmt.Errorf("failed to verify denylist signature: %w", err)
	}

	// Parse the JSON of the payload
	var entries []denylistEntry
	if err = json.Unmarshal(payload, &entries); err != nil {
		return fmt.Errorf("failed to parse denylist JSON: %w", err)
	}

	// Store the new denylist entries
	b.entries.Store(&entries)

	// Track when the denylist was last updated
	b.lastUpdated = time.Now()

	// Return a nil error as the denylist was successfully updated
	return nil
}

// download retrieves and parses the denylist
func (b *denylistImpl) download() ([]byte, error) {
	// Make an HTTP GET request for the denylist URL
	response, err := http.Get(b.url)
	if err != nil {
		return nil, fmt.Errorf("failed to download denylist: %w", err)
	}

	// Ensure the response body is cleaned up
	defer func() {
		if err = response.Body.Close(); err != nil {
			logger().Warn(err)
		}
	}()

	// Read the response body
	bytes, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	// Return the raw bytes from the response body
	return bytes, nil
}

// certKeyJWKThumbprint returns the JWK key fingerprint for the public key of an X509 certificate
func certKeyJWKThumbprint(cert *x509.Certificate) string {
	// Convert the key (any) to JWK. If that succeeds then return its fingerprint
	if key, _ := jwk.New(cert.PublicKey); key != nil {
		// Compute the fingerprint of the key
		jwk.AssignKeyID(key)

		// Retrieve the fingerprint, which annoyingly is an "any" return type
		fingerprint, _ := key.Get(jwk.KeyIDKey)

		// Use fmt to "convert" the fingerprint to a string
		return fmt.Sprintf("%s", fingerprint)
	}

	// If something above failed, default to an empty string. This would happen if the JWK library could not
	// understand the public key type, which would be a bizarre certificate.
	return ""
}

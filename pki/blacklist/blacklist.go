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
package blacklist

import (
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync/atomic"
	"time"

	config "github.com/nuts-foundation/nuts-node/pki/blacklist/config"

	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jws"
)

var (
	// ErrBlacklistMissing occurs when the blacklist cannot be downloaded
	ErrBlacklistMissing = errors.New("blacklist cannot be retrieved")

	// ErrCertBlacklisted means the certificate was blacklisted rather than revoked by a CRL
	ErrCertBlacklisted = errors.New("certificate is blacklisted")
)

type Blacklist interface {
	LastUpdated() time.Time
	Update() error
	URL() string
	ValidateCert(cert *x509.Certificate) error
}

// blacklistImpl implements arbitrary certificate rejection using issuer and serial number tuples
type blacklistImpl struct {
	// url specifies the URL where the blacklist is downloaded
	url string

	// entries is the decoded entries from the downloaded blacklist
	entries atomic.Pointer[[]blacklistEntry]

	// trustedKey is an Ed25519 key which must sign the blacklist
	trustedKey jwk.Key

	// lastUpdated contains the time the certificate was last updated
	lastUpdated time.Time
}

// blacklistEntry contains parameters for an X.509 certificate that must not be accepted for TLS connections
type blacklistEntry struct {
	// Issuer is a string representation (x509.Certificate.Issuer.String()) of the certificate
	Issuer string

	// SerialNumber is a string representation (x509.Certificate.SerialNumber.String()) of the certificate
	SerialNumber string

	// JWKThumbprint is an identifier of the public key per https://www.rfc-editor.org/rfc/rfc7638
	JWKThumbprint string
}

// New creates a blacklist with the specified configuration
func New(config config.Config) (Blacklist, error) {
	// "Disable" (operate in a NOP mode) the blacklist when the URL is empty
	if config.URL == "" {
		// Return the new blacklist and a nil error
		return &blacklistImpl{
			trustedKey: nil,
			url:        "",
		}, nil
	}

	// Parse the trusted key
	key, err := jwk.ParseKey([]byte(config.TrustedSigner), jwk.WithPEM(true))
	if err != nil {
		return nil, fmt.Errorf("failed to parse key: %w", err)
	}

	// Return the new blacklist and a nil error
	return &blacklistImpl{
		trustedKey: key,
		url:        config.URL,
	}, nil
}

// ValidateCert checks for the issuer and serialNumber in the blacklist, returning nil when the cert is permitted
// or an error when the cert is blacklisted or the blacklist cannot be retrieved
func (b *blacklistImpl) ValidateCert(cert *x509.Certificate) error {
	// Blacklists with an empty URL are a NOP
	if b.URL() == "" {
		return nil
	}

	// Extract the necessary information from the certificate
	issuer := cert.Issuer.String()
	serialNumber := cert.SerialNumber.String()

	// If the blacklist has not yet been downloaded, do so now
	if b.lastUpdated.IsZero() {
		// Trigger an update of the blacklist
		if err := b.Update(); err != nil {
			// If the blacklist download failed then log a message about it
			logger().WithError(err).
				WithField("Issuer", issuer).
				WithField("S/N", serialNumber).
				Error("cert validation failed because the blacklist cannot be downloaded")

			// Return an error indicating the blacklist cannot be retrieved
			return ErrBlacklistMissing
		}
	}

	// Fetch the entries
	entriesPtr := b.entries.Load()

	// The entries pointer should not be empty because of the lastUpdated check above
	if entriesPtr == nil {
		// If the entries still cannot be fetched then something is not right so return an error
		return ErrBlacklistMissing
	}

	// Check each entry in the blacklist for matches
	for _, entry := range *entriesPtr {
		// Check for this issuer and serial number combination
		if entry.Issuer == issuer && entry.SerialNumber == serialNumber {
			// Return an error indicating the certificate has been blacklisted
			return ErrCertBlacklisted
		}
	}

	// Return a nil error as the certificate hasn't been blacklisted
	return nil
}

func (b *blacklistImpl) LastUpdated() time.Time {
	return b.lastUpdated
}

func (b *blacklistImpl) URL() string {
	return b.url
}

// update downloads the blacklist, and updates the in-memory representation
func (b *blacklistImpl) Update() error {
	// Updating a blacklist with a URL is a NOP
	if b.URL() == "" {
		return nil
	}

	// Download the blacklist
	bytes, err := b.download()
	if err != nil {
		logger().WithError(err).
			WithField("URl", b.url).
			Warn("certiciate blacklist cannot be downloaded")
		return err
	}

	// Check the signature of the blacklist
	payload, err := jws.Verify(bytes, jwa.EdDSA, b.trustedKey)
	if err != nil {
		return fmt.Errorf("failed to verify blacklist signature: %w", err)
	}

	// Parse the JSON of the payload
	var entries []blacklistEntry
	if err = json.Unmarshal(payload, &entries); err != nil {
		return fmt.Errorf("failed to parse blacklist JSON: %w", err)
	}

	// Store the new blacklist entries
	b.entries.Store(&entries)

	// Track when the blacklist was last updated
	b.lastUpdated = time.Now()

	// Return a nil error as the blacklist was successfully updated
	return nil
}

// download retrieves and parses the blacklist
func (b *blacklistImpl) download() ([]byte, error) {
	// Make an HTTP GET request for the blacklist URL
	response, err := http.Get(b.url)
	if err != nil {
		return nil, fmt.Errorf("failed to download blacklist: %w", err)
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

// certKeyJWKFingerprint returns the JWK key fingerprint for the public key of an X509 certificate
func certKeyJWKFingerprint(cert *x509.Certificate) string {
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

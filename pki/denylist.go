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
	"fmt"
	"github.com/nuts-foundation/nuts-node/json"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
)

// denylistImpl implements arbitrary certificate rejection using issuer and serial number tuples
type denylistImpl struct {
	// url specifies the URL where the denylist is downloaded
	url string

	// entries is the decoded entries from the downloaded denylist
	entries atomic.Pointer[[]denylistEntry]

	// trustedKey is an Ed25519 key which must sign the denylist
	trustedKey jwk.Key

	// lastUpdated contains the time the certificate was last updated
	lastUpdated atomic.Pointer[time.Time]

	// subscribers for denylist updates
	subscribers []func()
}

// denylistEntry contains parameters for an X.509 certificate that must not be accepted for TLS connections
type denylistEntry struct {
	// Issuer is a string representation (x509.Certificate.Issuer.String()) of the certificate
	Issuer string `json:"issuer"`

	// SerialNumber is a string representation (x509.Certificate.SerialNumber.String()) of the certificate
	SerialNumber string `json:"serialnumber"`

	// JWKThumbprint is an identifier of the public key per https://www.rfc-editor.org/rfc/rfc7638
	JWKThumbprint string `json:"jwkthumbprint"`

	Reason string `json:"reason"`
}

// NewDenylist creates a denylist with the specified configuration
func NewDenylist(config DenylistConfig) (Denylist, error) {
	// initialize defaults
	dl := &denylistImpl{url: config.URL}
	dl.lastUpdated.Store(&time.Time{})

	// "Disable" (operate in a NOP mode) the denylist when the URL is empty
	if dl.url == "" {
		// Return the new denylist and a nil error
		return dl, nil
	}

	// Convert any literal '\n' in the PEM to an actual newline character
	trustedSigner := strings.ReplaceAll(config.TrustedSigner, "\\n", "\n")

	// Parse the trusted key
	key, err := jwk.ParseKey([]byte(trustedSigner), jwk.WithPEM(true))
	if err != nil {
		return nil, fmt.Errorf("failed to parse key: %w", err)
	}

	// Return the new denylist and a nil error
	dl.trustedKey = key
	return dl, nil
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
	if b.lastUpdated.Load().IsZero() {
		// Trigger an update of the denylist
		if err := b.Update(); err != nil {
			// If the denylist download failed then log a message about it
			logger().WithError(err).
				WithField("Issuer", issuer).
				WithField("S/N", serialNumber).
				WithField("Thumbprint", thumbprint).
				Error("Cert validation failed because the denylist cannot be downloaded")

			// Return an error indicating the denylist cannot be retrieved
			return ErrDenylistMissing
		}
	}

	// Fetch the entries
	entriesPtr := b.entries.Load()

	// The entries pointer should not be empty because of the lastUpdated check above
	if entriesPtr == nil {
		// If the entries still cannot be fetched then something is not right so return an error
		logger().Error("BUG: denylist entries pointer is nil")
		return ErrDenylistMissing
	}

	// Check each entry in the denylist for matches
	for _, entry := range *entriesPtr {
		// Check for this issuer and serial number combination
		if entry.Issuer == issuer && entry.SerialNumber == serialNumber && entry.JWKThumbprint == thumbprint {
			logger().
				WithField("Issuer", issuer).
				WithField("S/N", serialNumber).
				WithField("Thumbprint", thumbprint).
				Warn("Rejecting banned certificate")

			// Return an error indicating the certificate has been denylisted
			return ErrCertBanned
		}
	}

	// Log a message about the cert being validated
	logger().
		WithField("Issuer", issuer).
		WithField("S/N", serialNumber).
		WithField("Thumbprint", thumbprint).
		Trace("Validated certificate")

	// Return a nil error as the certificate hasn't been denylisted
	return nil
}

func (b *denylistImpl) LastUpdated() time.Time {
	return *b.lastUpdated.Load()
}

func (b *denylistImpl) URL() string {
	return b.url
}

// Update downloads the denylist, and updates the in-memory representation
func (b *denylistImpl) Update() error {
	// Updating a denylist with a URL is a NOP
	if b.URL() == "" {
		return nil
	}

	// Download the denylist
	bytes, err := b.download()
	if err != nil {
		logger().WithError(err).
			WithField("URL", b.url).
			Warn("Certificate denylist cannot be downloaded")
		return err
	}

	// Check the signature of the denylist
	payload, err := jws.Verify(bytes, jws.WithKey(jwa.EdDSA, b.trustedKey))
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
	now := nowFunc()
	b.lastUpdated.Store(&now)

	// Log when the denylist is updated
	logger().Debug("Denylist updated successfully")

	// Notify all subscribers synchronously
	for _, sub := range b.subscribers {
		sub()
	}

	// Return a nil error as the denylist was successfully updated
	return nil
}

func (b *denylistImpl) Subscribe(f func()) {
	b.subscribers = append(b.subscribers, f)
}

// download retrieves and parses the denylist
func (b *denylistImpl) download() ([]byte, error) {
	// Make an HTTP GET request for the denylist URL
	// We do not use our safe http client here since we're downloading from our own resource
	httpClient := http.Client{Timeout: syncTimeout}
	response, err := httpClient.Get(b.url)
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

	if key, _ := jwk.PublicKeyOf(cert.PublicKey); key != nil {
		// Compute the fingerprint of the key
		_ = jwk.AssignKeyID(key)

		// Retrieve the fingerprint, which annoyingly is an "any" return type
		fingerprint, _ := key.Get(jwk.KeyIDKey)

		// Use fmt to "convert" the fingerprint to a string
		return fmt.Sprintf("%s", fingerprint)
	}

	// If something above failed, default to an empty string. This would happen if the JWK library could not
	// understand the public key type, which would be a bizarre certificate.
	return ""
}

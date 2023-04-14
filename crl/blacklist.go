package crl

import (
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/nuts-foundation/nuts-node/crl/log"

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

// blacklist implements arbitrary certificate rejection using issuer and serial number tuples
type blacklist struct {
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

// newBlacklist creates a new blacklist with the specified url and trusted Ed25519 key in PEM format
func newBlacklist(URL string, trustedKeyPEM string) (*blacklist, error) {
	// Parse the trusted key
	key, err := jwk.ParseKey([]byte(trustedKeyPEM), jwk.WithPEM(true))
	if err != nil {
		return nil, fmt.Errorf("failed to parse key: %w", err)
	}

	// Return the new blacklist and a nil error
	return &blacklist{
		url:        URL,
		trustedKey: key,
	}, nil
}

// validateCert checks for the issuer and serialNumber in the blacklist, returning nil when the cert is permitted
// or an error when the cert is blacklisted or the blacklist cannot be retrieved
func (b *blacklist) validateCert(cert *x509.Certificate) error {
	// Extract the necessary information from the certificate
	issuer := cert.Issuer.String()
	serialNumber := cert.SerialNumber.String()

	// If the blacklist has not yet been downloaded, do so now
	if b.lastUpdated.IsZero() {
		// Trigger an update of the blacklist
		if err := b.update(); err != nil {
			// If the blacklist download failed then log a message about it
			log.Logger().WithError(err).
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

// update downloads the blacklist, and updates the in-memory representation
func (b *blacklist) update() error {
	// Download the blacklist
	bytes, err := b.download()
	if err != nil {
		log.Logger().WithError(err).
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
func (b *blacklist) download() ([]byte, error) {
	// Make an HTTP GET request for the blacklist URL
	response, err := http.Get(b.url)
	if err != nil {
		return nil, fmt.Errorf("failed to download blacklist: %w", err)
	}

	// Ensure the response body is cleaned up
	defer func() {
		if err = response.Body.Close(); err != nil {
			log.Logger().Warn(err)
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

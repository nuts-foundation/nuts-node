/*
 * Copyright (C) 2025 Nuts community
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

package client

import (
	"crypto/x509"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/crypto/hash"
	"github.com/nuts-foundation/nuts-node/http/log"
)

// ConfigureTrustBundle extends the trust bundle of the shared SafeHttpTransport with additional CA certificates
// loaded from the given directory, on top of the OS CA bundle. It loads all *.pem and *.crt files and logs the
// subject and SHA-256 fingerprint of each certificate.
// If dir is empty the feature is disabled and nothing is loaded. A configured directory that can't be read
// (including a non-existent directory) or that contains an invalid certificate file results in an error.
func ConfigureTrustBundle(dir string) error {
	if dir == "" {
		return nil
	}

	pool, err := x509.SystemCertPool()
	if err != nil {
		// SystemCertPool may fail on some platforms; fall back to an empty pool so the configured CAs are still trusted.
		log.Logger().WithError(err).Warn("Unable to load OS CA bundle for HTTP clients, only the additional CA certificates will be trusted")
		pool = x509.NewCertPool()
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("unable to read HTTP client trust bundle directory (dir=%s): %w", dir, err)
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		switch strings.ToLower(filepath.Ext(entry.Name())) {
		case ".pem", ".crt":
			// load it
		default:
			continue
		}
		filePath := filepath.Join(dir, entry.Name())
		data, err := os.ReadFile(filePath)
		if err != nil {
			return fmt.Errorf("unable to read HTTP client CA certificate (file=%s): %w", filePath, err)
		}
		certificates, err := core.ParseCertificates(data)
		if err != nil {
			return fmt.Errorf("unable to parse HTTP client CA certificate (file=%s): %w", filePath, err)
		}
		for _, certificate := range certificates {
			pool.AddCert(certificate)
			log.Logger().
				WithField("file", filePath).
				WithField("subject", certificate.Subject.String()).
				WithField("fingerprint", hash.SHA256Sum(certificate.Raw).String()).
				WithField("type", certificateKind(certificate)).
				Info("Trusting additional certificate for HTTP clients")
		}
	}

	SafeHttpTransport.TLSClientConfig.RootCAs = pool
	return nil
}

// certificateKind classifies a certificate as a root CA, intermediate CA or (non-CA) certificate for logging.
// They all end up in the same RootCAs pool: a TLS client only has a single trust anchor pool, so every loaded
// certificate is a trust anchor (intermediates presented by the server are used for chain building during the
// handshake). The classification mirrors core.BuildTrustStore and is purely informational.
func certificateKind(certificate *x509.Certificate) string {
	// Version 1 certificates lack basicConstraints.IsCA, so fall back to issuer == subject for those.
	if certificate.IsCA || certificate.Version == 1 {
		if certificate.Subject.String() == certificate.Issuer.String() {
			return "root CA"
		}
		return "intermediate CA"
	}
	return "certificate"
}

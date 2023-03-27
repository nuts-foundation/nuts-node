/*
 * Copyright (C) 2021 Nuts community
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

package crl

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"math"
	"math/big"
	"net/http"
	"sync"
	"time"

	"github.com/nuts-foundation/nuts-node/crl/log"
	"github.com/twmb/murmur3"
)

// Should be set to a number where the possibility for hash collisions is low
const defaultBitSetSize = 500

var nowFunc = time.Now

func hash(issuer string, serialNumber *big.Int) int64 {
	data := append([]byte(issuer), serialNumber.Bytes()...)
	sum := int64(murmur3.Sum64(data))

	return int64(math.Abs(float64(sum)))
}

// Validator synchronizes CRLs and validates revoked certificates
type Validator interface {
	// Sync downloads, updates, and verifies CRLs
	Sync() error
	// SyncLoop periodically calls Sync
	SyncLoop(ctx context.Context)
	// IsSynced returns whether all the CRLs are downloaded and are not outdated (based on the offset)
	IsSynced(maxOffsetDays int) bool
	// VerifyPeerCertificateFunction returns a tls.Config.VerifyPeerCertificate function based on given config
	VerifyPeerCertificateFunction(maxValidityDays int) func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error
	// IsRevoked checks whether the certificate was revoked. It does not check if the CRL IsSynced
	IsRevoked(issuer string, serialNumber *big.Int) bool
}

type validator struct {
	bitSet           *BitSet
	httpClient       *http.Client
	certificatesLock sync.RWMutex
	listsLock        sync.RWMutex
	certificates     map[string]*x509.Certificate
	lists            map[string]*x509.RevocationList
}

// NewValidator returns a new instance of the CRL database
func NewValidator(certificates []*x509.Certificate) Validator {
	return NewValidatorWithHTTPClient(certificates, http.DefaultClient)
}

// NewValidatorWithHTTPClient returns a new instance with a pre-configured HTTP client
func NewValidatorWithHTTPClient(certificates []*x509.Certificate, httpClient *http.Client) Validator {
	certMap := map[string]*x509.Certificate{}

	for _, certificate := range certificates {
		certMap[certificate.Subject.String()] = certificate
	}

	return &validator{
		httpClient:   httpClient,
		bitSet:       NewBitSet(defaultBitSetSize),
		certificates: certMap,
		lists:        map[string]*x509.RevocationList{},
	}
}

func (v *validator) setRevoked(issuer string, serialNumber *big.Int) {
	bitNum := hash(issuer, serialNumber) % int64(v.bitSet.Len())

	v.bitSet.Set(bitNum)
}

// IsRevoked checks whether the certificate was revoked or not
func (v *validator) IsRevoked(issuer string, serialNumber *big.Int) bool {
	bitNum := hash(issuer, serialNumber) % int64(v.bitSet.Len())
	if !v.bitSet.IsSet(bitNum) {
		return false
	}

	v.listsLock.RLock()
	defer v.listsLock.RUnlock()

	for _, list := range v.lists {
		listIssuerName := list.Issuer.String()

		for _, cert := range list.RevokedCertificates {
			if listIssuerName == issuer &&
				cert.SerialNumber.Cmp(serialNumber) == 0 {
				return true
			}
		}
	}

	return false
}

func (v *validator) updateCRL(endpoint string) error {
	v.listsLock.RLock()
	crl, ok := v.lists[endpoint]
	v.listsLock.RUnlock()

	if !ok || crlHasExpired(crl, nowFunc()) {
		return v.downloadCRL(endpoint)
	}

	return nil
}

func (v *validator) verifyCRL(crl *x509.RevocationList) error {
	v.certificatesLock.RLock()
	defer v.certificatesLock.RUnlock()

	issuerName := crl.Issuer.String()

	certificate, ok := v.certificates[issuerName]
	if !ok {
		return errors.New("CRL signature could not be validated against known certificates")
	}

	return crl.CheckSignatureFrom(certificate)
}

func (v *validator) downloadCRL(endpoint string) error {
	response, err := v.httpClient.Get(endpoint)
	if err != nil {
		return err
	}

	defer response.Body.Close()

	data, err := io.ReadAll(response.Body)
	if err != nil {
		return fmt.Errorf("unable to download CRL (url=%s): %w", endpoint, err)
	}

	crl, err := x509.ParseRevocationList(data)
	if err != nil {
		return fmt.Errorf("unable to parse downloaded CRL (url=%s): %w", endpoint, err)
	}

	if err := v.verifyCRL(crl); err != nil {
		return fmt.Errorf("CRL verification failed (issuer=%s): %w", crl.Issuer.String(), err)
	}

	v.listsLock.Lock()
	defer v.listsLock.Unlock()

	issuerName := crl.Issuer.String()

	for _, cert := range crl.RevokedCertificates {
		v.setRevoked(issuerName, cert.SerialNumber)
	}

	v.lists[endpoint] = crl

	return nil
}

// crlHasExpired is a replacement for pkix.CertificateList.HasExpired
func crlHasExpired(crl *x509.RevocationList, deadline time.Time) bool {
	return !deadline.Before(crl.NextUpdate)
}

// IsSynced returns whether all the CRLs are downloaded and are not outdated (based on the offset)
func (v *validator) IsSynced(maxOffsetDays int) bool {
	endpoints := v.parseCRLEndpoints()

	v.listsLock.RLock()
	defer v.listsLock.RUnlock()

	// Check if all CRLs have been downloaded, but if ignore CRL endpoints that are only used by expired certificates.
	for endpoint, dependingCAs := range endpoints {
		if !anyCertificateActive(dependingCAs) {
			continue
		}
		// downloaded?
		if _, ok := v.lists[endpoint]; !ok {
			return false
		}
	}

	// Verify that none of the CRLs are outdated
	now := nowFunc().Add(time.Duration(-maxOffsetDays) * (time.Hour * 24))

	for _, list := range v.lists {
		if crlHasExpired(list, now) {
			return false
		}
	}

	return true
}

// anyCertificateActive returns true if any of the certificates is not expired. If the list is empty, it returns false.
func anyCertificateActive(certs []*x509.Certificate) bool {
	result := false
	for _, cert := range certs {
		if nowFunc().After(cert.NotAfter) {
			log.Logger().Warnf("Trust store contains expired certificate: %s (s/n: %s)", cert.Subject.String(), cert.SerialNumber.String())
		} else {
			// Certificate is active
			result = true
		}
	}
	return result
}

func (v *validator) appendCertificates(certificates []*x509.Certificate) {
	v.certificatesLock.Lock()
	defer v.certificatesLock.Unlock()

	for _, certificate := range certificates {
		subject := certificate.Subject.String()

		if _, ok := v.certificates[subject]; !ok {
			v.certificates[subject] = certificate
		}
	}
}

func (v *validator) VerifyPeerCertificateFunction(maxValidityDays int) func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
	return func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
		// Import unknown certificates
		var verifiedCerts []*x509.Certificate

		for _, chain := range verifiedChains {
			for _, verifiedCert := range chain {
				if verifiedCert.IsCA {
					verifiedCerts = append(verifiedCerts, verifiedCert)
				}
			}
		}

		v.appendCertificates(verifiedCerts)

		// Parse certificates and check if they are revoked
		var raw []byte

		for _, rawCert := range rawCerts {
			raw = append(raw, rawCert...)
		}

		certificates, err := x509.ParseCertificates(raw)
		if err != nil {
			return err
		}

		for _, certificate := range certificates {
			if v.IsRevoked(certificate.Issuer.String(), certificate.SerialNumber) {
				return fmt.Errorf("certificate with issuer '%s' is revoked: %s", certificate.Issuer.String(), certificate.Subject.String())
			}
		}

		// If the CRL validator is outdated kill the connection
		if !v.IsSynced(maxValidityDays) {
			return errors.New("CRL database is outdated, certificate revocation can't be checked")
		}

		return nil
	}
}

// parseCRLEndpoints parses the CRLDistributionPoints from registered CA certificates and returns them.
// Since multiple CA certificates might use the same CRL (although improbable), it is returned as list.
func (v *validator) parseCRLEndpoints() map[string][]*x509.Certificate {
	v.certificatesLock.RLock()
	defer v.certificatesLock.RUnlock()

	var result = make(map[string][]*x509.Certificate)
	for _, certificate := range v.certificates {
		for _, endpoint := range certificate.CRLDistributionPoints {
			result[endpoint] = append(result[endpoint], certificate)
		}
	}

	return result
}

// Sync downloads, updates and verifies CRLs
func (v *validator) Sync() error {
	endpoints := v.parseCRLEndpoints()

	wc := sync.WaitGroup{}
	wc.Add(len(endpoints))

	errorsChan := make(chan error)

	go func() {
		wc.Wait()
		close(errorsChan)
	}()

	for endpoint, dependingCAs := range endpoints {
		if !anyCertificateActive(dependingCAs) {
			// No active certificates depending on this CRL endpoint
			wc.Done()
			continue
		}

		go func(endpoint string) {
			defer wc.Done()

			if err := v.updateCRL(endpoint); err != nil {
				errorsChan <- err
			}
		}(endpoint)
	}

	var syncErrors []error

	for err := range errorsChan {
		syncErrors = append(syncErrors, err)
	}

	if len(syncErrors) == 0 {
		return nil
	}

	return &SyncError{errors: syncErrors}
}

func (v *validator) SyncLoop(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()

	processLoop:
		for {
			select {
			case <-ctx.Done():
				break processLoop
			case <-ticker.C:
				if err := v.Sync(); err != nil {
					log.Logger().Errorf("CRL synchronization failed: %s", err.Error())
				}
			}
		}
	}()
}

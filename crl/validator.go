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
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"github.com/sirupsen/logrus"
	"io/ioutil"
	"math"
	"math/big"
	"net/http"
	"sync"
	"time"

	"github.com/spaolacci/murmur3"
)

// Should be set to a number where the possibility for hash collisions is low
const defaultBitSetSize = 500

func hash(issuer string, serialNumber *big.Int) int64 {
	data := append([]byte(issuer), serialNumber.Bytes()...)
	sum := int64(murmur3.Sum64(data))

	return int64(math.Abs(float64(sum)))
}

// Validator synchronizes CRLs and validates revoked certificates
type Validator interface {
	Sync() error
	SyncLoop(ctx context.Context)
	IsSynced(maxOffsetDays int) bool
	Configure(config *tls.Config, maxValidityDays int)
	IsRevoked(issuer string, serialNumber *big.Int) bool
}

type validator struct {
	bitSet           *BitSet
	httpClient       *http.Client
	certificatesLock sync.RWMutex
	listsLock        sync.RWMutex
	certificates     map[string]*x509.Certificate
	lists            map[string]*pkix.CertificateList
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
		lists:        map[string]*pkix.CertificateList{},
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
		listIssuerName := list.TBSCertList.Issuer.String()

		for _, cert := range list.TBSCertList.RevokedCertificates {
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

	if !ok || crl.HasExpired(time.Now()) {
		return v.downloadCRL(endpoint)
	}

	return nil
}

func (v *validator) verifyCRL(crl *pkix.CertificateList) error {
	v.certificatesLock.RLock()
	defer v.certificatesLock.RUnlock()

	issuerName := crl.TBSCertList.Issuer.String()

	certificate, ok := v.certificates[issuerName]
	if !ok {
		return errors.New("CRL signature could not be validated against known certificates")
	}

	return certificate.CheckCRLSignature(crl)
}

func (v *validator) downloadCRL(endpoint string) error {
	response, err := v.httpClient.Get(endpoint)
	if err != nil {
		return err
	}

	defer response.Body.Close()

	data, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return err
	}

	crl, err := x509.ParseCRL(data)
	if err != nil {
		return err
	}

	if err := v.verifyCRL(crl); err != nil {
		return err
	}

	v.listsLock.Lock()
	defer v.listsLock.Unlock()

	issuerName := crl.TBSCertList.Issuer.String()

	for _, cert := range crl.TBSCertList.RevokedCertificates {
		v.setRevoked(issuerName, cert.SerialNumber)
	}

	v.lists[endpoint] = crl

	return nil
}

// IsSynced returns whether all the CRLs are downloaded and are not outdated (based on the offset)
func (v *validator) IsSynced(maxOffsetDays int) bool {
	endpoints := v.parseCRLEndpoints()

	v.listsLock.RLock()
	defer v.listsLock.RUnlock()

	// Check if all CRLs have been downloaded
	for _, endpoint := range endpoints {
		if _, ok := v.lists[endpoint]; !ok {
			return false
		}
	}

	// Verify that none of the CRLs are outdated
	now := time.Now().Add(time.Duration(-maxOffsetDays) * (time.Hour * 24))

	for _, list := range v.lists {
		if list.HasExpired(now) {
			return false
		}
	}

	return true
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

// Configure adds a callback to the TLS config to check if the peer certificate was revoked
func (v *validator) Configure(config *tls.Config, maxValidityDays int) {
	config.VerifyPeerCertificate = func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
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

func (v *validator) parseCRLEndpoints() (endpoints []string) {
	v.certificatesLock.RLock()
	defer v.certificatesLock.RUnlock()

	for _, certificate := range v.certificates {
	lookup:
		for _, endpoint := range certificate.CRLDistributionPoints {
			for _, existingEndpoint := range endpoints {
				if endpoint == existingEndpoint {
					continue lookup
				}
			}

			endpoints = append(endpoints, endpoint)
		}
	}

	return
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

	for _, endpoint := range endpoints {
		go func(e string) {
			defer wc.Done()

			if err := v.updateCRL(e); err != nil {
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

	processLoop:
		for {
			select {
			case <-ctx.Done():
				break processLoop
			case <-ticker.C:
				if err := v.Sync(); err != nil {
					logrus.Errorf("CRL synchronization failed: %s", err.Error())
				}
			}
		}
	}()
}

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

package crl

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/nuts-foundation/nuts-node/crl/log"
)

var nowFunc = time.Now

// RFC008 §3.3: "... A node MUST at least update all CRLs every hour."
// We try to update every hour, no guarantee that it succeeds.
const syncInterval = time.Hour

// errors
var (
	ErrCRLMissing  = errors.New("crl is missing")
	ErrCRLExpired  = errors.New("crl has expired")
	ErrCertRevoked = errors.New("certificate is revoked")
	ErrCertInvalid = errors.New("certificate is not valid")
)

type Validator interface {
	// Start downloading CRLs. Cancelling the context will stop the Validator.
	Start(ctx context.Context)

	// Validate returns an error if any of the certificates in the chain has been revoked, or if the request cannot be processed.
	// ErrCertRevoked and ErrCertInvalid indicates that at least one of the certificates is revoked or otherwise invalid.
	// ErrCRLMissing and ErrCRLExpired signal that at least one of the certificates cannot be validated reliably.
	// If the certificate was revoked on an expired CRL, it wil return ErrCertRevoked. Ignoring ErrCRLMissing and ErrCRLExpired changes the behavior from hard-fail to soft-fail.
	// The certificate chain is expected to be sorted leaf to root.
	// Calling Validate before Start results in an error.
	Validate(chian []*x509.Certificate) error

	// SetValidatePeerCertificateFunc sets config.ValidatePeerCertificate to use Validate and MUST be called before Start.
	// Returns an error when config.Certificates contain certificates that cannot be parsed,
	// or are signed by CAs that are not in the Validator's truststore.
	SetValidatePeerCertificateFunc(config *tls.Config) error
}

type validator struct {
	// started is true once Start is called. Will be set to false if the context is cancelled.
	started bool
	// httpClient downloads the CRLs
	httpClient *http.Client
	// truststore maps Certificate.Subject.String() to their certificate.
	// Used for CRL signature checking. Immutable once Start() has been called.
	truststore map[string]*x509.Certificate
	// crlChan protects crls from race conditions, both are private
	// All operations on crls should be in the func sent to the channel.
	crlChan chan func()
	// crls maps CRL endpoints to their x509.RevocationList
	crls map[string]*revocationList
}

type revocationList struct {
	// list is the actual revocationList
	list *x509.RevocationList
	// revoked contains all revoked certificates index by their serial number (pkix.RevokedCertificate.SerialNumber.String())
	revoked map[string]bool
	// issuers of the CRL found at this endpoint. Multiple issuers could indicate MITM attack, or re-use of an endpoint.
	issuers []*x509.Certificate
	// lastUpdated is the timestamp that list was last updated. (When this instance was of revocationList was created)
	lastUpdated time.Time
}

func newRevocationList(cert *x509.Certificate) *revocationList {
	return &revocationList{
		list:    new(x509.RevocationList),
		revoked: make(map[string]bool, 0),
		issuers: []*x509.Certificate{cert},
	}
}

// NewValidator returns a new CRL validator.
func NewValidator(truststore []*x509.Certificate) Validator {
	return newValidatorWithHTTPClient(truststore, http.DefaultClient)
}

// NewValidatorWithHTTPClient returns a new instance with a pre-configured HTTP client
func newValidatorWithHTTPClient(certificates []*x509.Certificate, client *http.Client) *validator {
	certMap := make(map[string]*x509.Certificate, len(certificates))
	listMap := map[string]*revocationList{}

	for _, certificate := range certificates {
		certMap[certificate.Subject.String()] = certificate
	}
	for _, certificate := range certificates {
		issuer := certMap[certificate.Issuer.String()]
		for _, endpoint := range certificate.CRLDistributionPoints {
			listMap[endpoint] = newRevocationList(issuer)
		}
	}
	return &validator{
		httpClient: client,
		crlChan:    make(chan func()), // unbuffered
		truststore: certMap,
		crls:       listMap,
	}
}

func (v *validator) Start(ctx context.Context) {
	v.started = true
	// start action loop. This processes crl updates and revocation checks
	go v.validatorLoop(ctx)
	// start sync loop. this only downloads the data
	go v.syncLoop(ctx)
}

func (v *validator) syncLoop(ctx context.Context) {
	ticker := time.NewTicker(syncInterval)
	defer ticker.Stop()
	v.sync() // first tick is after the interval
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			v.sync()
		}
	}
}

func (v *validator) validatorLoop(ctx context.Context) {
	var f func()
	var ok bool
	for {
		select {
		case <-ctx.Done():
			v.started = false
			return
		case f, ok = <-v.crlChan:
			if ok {
				f()
			}
		}
	}
}

func (v *validator) Validate(chain []*x509.Certificate) error {
	if !v.started {
		return errors.New("CRL validator is not started")
	}
	return v.validateChain(chain)
}

func (v *validator) SetValidatePeerCertificateFunc(config *tls.Config) error {
	if v.started {
		return errors.New("SetVerifyPeerCertificateFunc must be called before Start")
	}

	parseCertificatesSlice := func(rawCerts [][]byte) ([]*x509.Certificate, error) {
		var raw []byte
		for _, rawCert := range rawCerts {
			raw = append(raw, rawCert...)
		}
		return x509.ParseCertificates(raw)
	}

	// check that all cert issuers are in the truststore, and add missing crl distribution points.
	for _, chain := range config.Certificates {
		certificates, err := parseCertificatesSlice(chain.Certificate)
		if err != nil {
			return err
		}
		for _, cert := range certificates {
			issuer := v.truststore[cert.Issuer.String()]
			if issuer == nil {
				// This indicates a mismatch between crlValidator truststore and tls.Config. This is a programming error.
				return errors.New("tls.Config contains certificate from issuer that is not in the truststore: " + cert.Subject.String())
			}
			// add any previously unknown CRL distribution points.
			// (Leaf cert is likely to contain CRLDistributionPoints not found in the truststore.)
			if len(cert.CRLDistributionPoints) > 0 {
				for _, endpoint := range cert.CRLDistributionPoints {
					if v.crls[endpoint] == nil {
						// pre-start, can't use setCRL
						v.crls[endpoint] = newRevocationList(issuer)
					}
				}
			}
		}
	}

	config.VerifyPeerCertificate = func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
		// TODO: the truststore should already contain ALL CAs that might be found in the verifiedChains
		// TODO: should we check rawCerts, or verified chains?
		// rawCerts contains raw cert data from the tls handshake.
		// It is used together with the tls.Config to generate verifiedChains, but may contain additional certs that are not in a verified chain.

		certificates, err := parseCertificatesSlice(rawCerts)
		if err != nil {
			return err
		}

		return v.Validate(certificates)
	}
	return nil
}

// validateChain validates that none of the certificates in the chain is revoked.
// Certificated in chain are assumed ordered from leaf to root certificate. (always true for calls to VerifyPeerCertificate)
func (v *validator) validateChain(chain []*x509.Certificate) error {
	var cert *x509.Certificate
	var err error
	for i := range chain {
		cert = chain[len(chain)-1-i]
		// check in reverse order to prevent CRL expiration errors due to revoked CAs no longer issuing CRLs
		if err = v.validateCert(cert); err != nil {
			return fmt.Errorf("%w: subject=%s, S/N=%s, issuer=%s", err, cert.Subject.String(), cert.SerialNumber.String(), cert.Issuer.String())
		}
	}
	return nil
}

func (v *validator) validateCert(cert *x509.Certificate) error {
	if nowFunc().Before(cert.NotBefore) || nowFunc().After(cert.NotAfter) {
		return ErrCertInvalid
	}
	for _, endpoint := range cert.CRLDistributionPoints {
		crl, ok := v.getCRL(endpoint)
		if ok && crl.revoked[cert.SerialNumber.String()] {
			// revocation takes precedence over an internal error.
			return ErrCertRevoked
		}
		if !ok || crl.lastUpdated.IsZero() {
			// TODO: async or not? This method call is the result of a client request running in its own go routine. We can wait for the crl to be downloaded...
			// Currently the request fails on the first request using a certificate with an unknown CRl endpoint
			go v.updateCRL(endpoint, nil)
			return ErrCRLMissing
		}
		if !nowFunc().Before(crl.list.NextUpdate) {
			// CA expiration is checked earlier in the chain
			return ErrCRLExpired
		}
	}
	return nil
}

// getCRLs returns a copy of the crls map.
// The returned revocationList must not be updated, use setCRL for this.
func (v *validator) getCRLs() map[string]*revocationList {
	result := make(chan map[string]*revocationList, 1) // buffer size of 1 so the loop never blocks
	v.crlChan <- func() {
		defer close(result)
		cp := make(map[string]*revocationList, len(v.crls))
		for ep, crl := range v.crls {
			cp[ep] = crl
		}
		result <- cp
	}
	return <-result
}

// getCRL returns the requested crls in a save way, or returns false if it does not exist
func (v *validator) getCRL(endpoint string) (*revocationList, bool) {
	type resultStruct struct {
		rl     *revocationList
		exists bool
	}
	result := make(chan resultStruct, 1) // buffer size of 1 so the loop never blocks
	v.crlChan <- func() {
		defer close(result)
		out := resultStruct{}
		out.rl, out.exists = v.crls[endpoint]
		result <- out
	}
	out := <-result
	return out.rl, out.exists // make blocking call
}

// setCRL updates crls in a save way
func (v *validator) setCRL(endpoint string, crl *revocationList) {
	result := make(chan struct{}, 1) // buffer size of 1 so the loop never blocks
	v.crlChan <- func() {
		defer close(result)
		v.crls[endpoint] = crl
		result <- struct{}{}
	}
	<-result // make blocking call
}

// sync tries to update all crls
func (v *validator) sync() {
	// get a copy of the CRL map, the contents should not be changed directly.
	crlMap := v.getCRLs()

	// TODO: does this need a WaitGroup?
	wg := &sync.WaitGroup{}
	wg.Add(len(crlMap))

	// Update in parallel if at least one of the issuers is still valid
	for endpoint, current := range crlMap {
		if len(current.issuers) > 0 && !anyCertificateActive(current.issuers...) {
			wg.Done()
			continue
		}

		go func(ep string, crl *revocationList, wg *sync.WaitGroup) {
			err := v.updateCRL(ep, crl)
			if err != nil {
				// Connections containing a certificate pointing to this CRL will be accepted until its current.list.NextUpdate.
				if crl != nil || time.Since(crl.lastUpdated) > 4*time.Hour {
					// Escalate to error logging if the CRL is missing or fails to update in several hours.
					log.Logger().WithError(err).WithField("CRLDistributionPoint", ep).Error("Update CRL")
				} else {
					log.Logger().WithError(err).WithField("CRLDistributionPoint", ep).Debug("Update CRL")
				}
			}
			wg.Done()
		}(endpoint, current, wg)
	}

	wg.Wait()
}

// updateCRL downloads the CRL from endpoint, and updates the revocationList in crls if it is newer than current
func (v *validator) updateCRL(endpoint string, current *revocationList) error {
	// download CRL
	crl, err := v.downloadCRL(endpoint)
	if err != nil {
		return err
	}

	// verify signature
	if err = v.verifyCRL(crl); err != nil {
		return err
	}

	// update when it is a new clr
	if current == nil || current.list.Number == nil || current.list.Number.Cmp(crl.Number) < 0 {
		// parse revocations
		revoked := make(map[string]bool, len(crl.RevokedCertificates))
		for _, rev := range crl.RevokedCertificates {
			revoked[rev.SerialNumber.String()] = true
		}
		// update issuers of CRL
		issuers := []*x509.Certificate{}
		if current != nil {
			copy(issuers, current.issuers)
		}
		isNewIssuer := true
		for _, iss := range issuers {
			if iss.Issuer.String() == crl.Issuer.String() {
				isNewIssuer = false
				break
			}
		}
		if isNewIssuer {
			// must occur in truststore or verifyCRL would have failed
			issuers = append(issuers, v.truststore[crl.Issuer.String()])
		}
		// set the new CRL
		v.setCRL(endpoint, &revocationList{
			list:        crl,
			issuers:     issuers,
			revoked:     revoked,
			lastUpdated: nowFunc(),
		})
	}
	return nil
}

// downloadCRL downloads and parses the CRL
func (v *validator) downloadCRL(endpoint string) (*x509.RevocationList, error) {
	response, err := v.httpClient.Get(endpoint)
	if err != nil {
		return nil, fmt.Errorf("downloading CRL: %w", err)
	}
	defer func() {
		if err = response.Body.Close(); err != nil {
			log.Logger().Warn(err)
		}
	}()

	data, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, fmt.Errorf("downloading CRL: %w", err)
	}

	crl, err := x509.ParseRevocationList(data)
	if err != nil {
		return nil, fmt.Errorf("parse downloaded CRL: %w", err)
	}

	return crl, nil
}

// verifyCRL checks the signature on the CRL with the issuer. Returns an error if the issuers is not in the truststore.
func (v *validator) verifyCRL(crl *x509.RevocationList) error {
	certificate, ok := v.truststore[crl.Issuer.String()]
	if !ok {
		return errors.New("signature could not be validated against known certificates")
	}
	err := crl.CheckSignatureFrom(certificate)
	if err != nil {
		return fmt.Errorf("crl signature could not be verified: %w", err)
	}
	return nil
}

// anyCertificateActive returns true if any of the certificates is not expired. If the list is empty, it returns false.
func anyCertificateActive(certs ...*x509.Certificate) bool {
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

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
	"strings"
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
	ErrCRLMissing    = errors.New("crl is missing")
	ErrCRLExpired    = errors.New("crl has expired")
	ErrCertRevoked   = errors.New("certificate is revoked")
	ErrCertInvalid   = errors.New("certificate is not valid")
	ErrCertUntrusted = errors.New("certificate's issuer is not trusted'")
)

type Validator interface {
	// Start downloading CRLs. Cancelling the context will stop the Validator.
	Start(ctx context.Context)

	// Validate returns an error if any of the certificates in the chain has been revoked, or if the request cannot be processed.
	// ErrCertRevoked, ErrCertUntrusted and ErrCertInvalid indicates that at least one of the certificates is revoked,
	// signed by a CA that is not in the truststore, or is otherwise invalid.
	// ErrCRLMissing and ErrCRLExpired signal that at least one of the certificates cannot be validated reliably.
	// If the certificate was revoked on an expired CRL, it wil return ErrCertRevoked. Ignoring ErrCRLMissing and ErrCRLExpired changes the behavior from hard-fail to soft-fail.
	// The certificate chain is expected to be sorted leaf to root.
	// Calling Validate before Start results in an error.
	Validate(chain []*x509.Certificate) error

	// SetValidatePeerCertificateFunc sets config.ValidatePeerCertificate to use Validate.
	// Returns an error when config.Certificates contain certificates that cannot be parsed,
	// or are signed by CAs that are not in the Validator's truststore.
	SetValidatePeerCertificateFunc(config *tls.Config) error
}

type validator struct {
	// httpClient downloads the CRLs
	httpClient *http.Client
	// truststore maps Certificate.Subject.String() to their certificate.
	// Used for CRL signature checking. Immutable once Start() has been called.
	truststore map[string]*x509.Certificate
	// crls maps CRL endpoints to their x509.RevocationList
	crls sync.Map
}

type revocationList struct {
	// list is the actual revocationList
	list *x509.RevocationList
	// revoked contains all revoked certificates index by their serial number (pkix.RevokedCertificate.SerialNumber.String())
	revoked map[string]bool
	// issuer of the CRL found at this endpoint. Multiple issuers could indicate MITM attack, or re-use of an endpoint.
	issuer *x509.Certificate
	// lastUpdated is the timestamp that list was last updated. (When this instance was of revocationList was created)
	lastUpdated time.Time
}

func newRevocationList(cert *x509.Certificate) *revocationList {
	return &revocationList{
		list:    new(x509.RevocationList),
		revoked: make(map[string]bool, 0),
		issuer:  cert,
	}
}

// New returns a new CRL validator.
func New(truststore []*x509.Certificate) Validator {
	return newValidatorWithHTTPClient(truststore, http.DefaultClient)
}

// NewValidatorWithHTTPClient returns a new instance with a pre-configured HTTP client
func newValidatorWithHTTPClient(certificates []*x509.Certificate, client *http.Client) *validator {
	val := &validator{
		httpClient: client,
		truststore: map[string]*x509.Certificate{},
	}
	// add truststore
	for _, certificate := range certificates {
		if _, ok := val.truststore[certificate.Subject.String()]; ok {
			// skip duplicates
			continue
		}
		val.truststore[certificate.Subject.String()] = certificate
	}
	// add CRL distribution points
	for _, certificate := range val.truststore {
		issuer, ok := val.truststore[certificate.Issuer.String()]
		if !ok {
			err := fmt.Errorf("certificate's issuer is not in the trust store: subject=%s, issuer=%s", certificate.Subject.String(), certificate.Issuer.String())
			panic(err)
		}
		err := val.addEndpoints(issuer, certificate.CRLDistributionPoints)
		if err != nil {
			panic(err)
		}
	}
	return val
}

func (v *validator) Start(ctx context.Context) {
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

func (v *validator) Validate(chain []*x509.Certificate) error {
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

func (v *validator) SetValidatePeerCertificateFunc(config *tls.Config) error {
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
				return fmt.Errorf("tls.Config contains certificate from issuer that is not in the truststore: %s", cert.Subject.String())
			}
			if err = cert.CheckSignatureFrom(issuer); err != nil {
				return fmt.Errorf("tls.Config contains cetificate with invalid signature: subject=%s", cert.Subject.String())
			}
			// add any previously unknown CRL distribution points.
			// (Leaf cert is likely to contain CRLDistributionPoints not found in the truststore.)
			if err = v.addEndpoints(issuer, cert.CRLDistributionPoints); err != nil {
				return err
			}
		}
	}

	config.VerifyPeerCertificate = func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
		// TODO: should we check rawCerts, or verified chains?
		// rawCerts contains raw certificate data presented by the peer during the tls handshake.
		// It is used together with the tls.Config to generate verifiedChains, but may contain additional certs that are not in a verified chain.
		// So the question is, do we reject a client if it sends ANY invalid certificate, even if it is not part of a verifiedChain?
		// (A peer could participate in multiple networks and send multiple client certs of which some are not part of our truststore.
		// This would result in an error, however, I think just sending all client certs violates tls handshake specifications and,
		// it is currently technically not possible to configure multiple client certs in the nuts node anyway.)

		certificates, err := parseCertificatesSlice(rawCerts)
		if err != nil {
			return err
		}

		return v.Validate(certificates)
	}
	return nil
}

func (v *validator) validateCert(cert *x509.Certificate) error {
	if nowFunc().Before(cert.NotBefore) || nowFunc().After(cert.NotAfter) {
		return ErrCertInvalid
	}
	for _, endpoint := range cert.CRLDistributionPoints {
		crl, ok := v.getCRL(endpoint)

		// add distribution endpoint if unknown
		if !ok {
			var issuer *x509.Certificate
			issuer, ok = v.truststore[cert.Issuer.String()]
			if !ok {
				return ErrCertUntrusted
			}
			err := v.addEndpoints(issuer, []string{endpoint})
			if err != nil {
				log.Logger().WithError(err).
					WithField("Subject", cert.Subject.String()).
					WithField("S/N", cert.SerialNumber.String()).
					Warn("cert validation failed because CRL cannot be added")
				return ErrCRLMissing
			}
			// update loop params
			crl, _ = v.getCRL(endpoint) // must be present now
		}

		// initial download if missing
		if crl.lastUpdated.IsZero() {
			// Pause validate to download CRL. Client requests run in their own go routine, so we can afford to wait.
			err := v.updateCRL(endpoint, crl)
			if err != nil {
				log.Logger().WithError(err).
					WithField("Subject", cert.Subject.String()).
					WithField("S/N", cert.SerialNumber.String()).
					Warn("cert validation failed because CRL cannot be updated")
				return ErrCRLMissing
			}
			// update loop params
			crl, _ = v.getCRL(endpoint) // must be present
		}

		// check certificate revocation
		if crl.revoked[cert.SerialNumber.String()] {
			// revocation takes precedence over expired CRL.
			return ErrCertRevoked
		}

		// check CRL status
		if !nowFunc().Before(crl.list.NextUpdate) {
			// CA expiration is checked earlier in the chain
			return ErrCRLExpired
		}
	}
	return nil
}

// addEndpoint adds the CRL endpoint if it does not exist. Returns an error if the CRL issuer does not match the expected issuer.
func (v *validator) addEndpoints(certIssuer *x509.Certificate, endpoints []string) error {
	for _, endpoint := range endpoints {
		if crl, ok := v.getCRL(endpoint); ok {
			if strings.Compare(crl.issuer.Subject.String(), certIssuer.Subject.String()) != 0 {
				// We assume that an endpoint can only issue CRLs from a single CA because:
				// If an endpoint hosts multiple CRLs, how would the server know what CRL to present?
				// Endpoint reuse by CAs is not an issue. CAs host the CRL for some time after the CA has expired, immediate reuse result in the previous point.
				return fmt.Errorf("multiple issuers known for CRL distribution endpoint=%s, issuers=%s,%s", endpoints, crl.issuer.Subject.String(), certIssuer.Subject.String())
			}
			// already exists
			continue
		}
		// TODO: Optimize by starting Go routine per endpoint to update the CRL. A Go routine per CRL prevents all CRLs being updated simultaneously.
		v.crls.Store(endpoint, newRevocationList(certIssuer))
	}
	return nil
}

// getCRL returns the requested crls in a save way, or returns false if it does not exist
func (v *validator) getCRL(endpoint string) (*revocationList, bool) {
	value, ok := v.crls.Load(endpoint)
	if !ok {
		return nil, false
	}
	return value.(*revocationList), true
}

// sync tries to update all crls
func (v *validator) sync() {
	wg := &sync.WaitGroup{}
	// Update in parallel if at least one of the issuers is still valid
	v.crls.Range(func(endpoint2, current2 any) bool {
		endpoint, isString := endpoint2.(string)
		current, isCRL := current2.(*revocationList)
		if !isString || !isCRL {
			// should never happen
			log.Logger().
				WithField("endpoint", fmt.Sprintf("%v", endpoint2)).
				WithField("CRL", fmt.Sprintf("%v", current2)).
				Error("crl validator is invalid")
			// TODO: should this just panic?
			return true
		}
		if nowFunc().Before(current.issuer.NotBefore) || nowFunc().After(current.issuer.NotAfter) {
			log.Logger().Warnf("Trust store contains invalid certificate: %s (s/n: %s)", current.issuer.Subject.String(), current.issuer.SerialNumber.String())
			return true
		}
		wg.Add(1)
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

		return true
	})
	wg.Wait()
}

// updateCRL downloads the CRL from endpoint, and updates the revocationList in crls if it is newer than the current CRL
func (v *validator) updateCRL(endpoint string, current *revocationList) error {
	// download CRL
	crl, err := v.downloadCRL(endpoint)
	if err != nil {
		return err
	}

	// verify signature
	if err = v.verifyCRL(crl, current.issuer); err != nil {
		return err
	}

	// update when it is a new clr
	if current.list.Number == nil || current.list.Number.Cmp(crl.Number) < 0 {
		// parse revocations
		revoked := make(map[string]bool, len(crl.RevokedCertificates))
		for _, rev := range crl.RevokedCertificates {
			revoked[rev.SerialNumber.String()] = true
		}
		// set the new CRL
		v.crls.Store(endpoint, &revocationList{
			list:        crl,
			issuer:      current.issuer,
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
func (v *validator) verifyCRL(crl *x509.RevocationList, expectedIssuer *x509.Certificate) error {
	// update issuers of CRL
	if strings.Compare(expectedIssuer.Subject.String(), crl.Issuer.String()) != 0 {
		return fmt.Errorf("crl signed by unexpected issuer: expected=%s, got=%s", expectedIssuer.Subject.String(), crl.Issuer.String())
	}
	err := crl.CheckSignatureFrom(expectedIssuer)
	if err != nil {
		return fmt.Errorf("crl signature could not be verified: %w", err)
	}
	return nil
}

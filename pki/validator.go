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

	pkiconfig "github.com/nuts-foundation/nuts-node/pki/config"
)

var nowFunc = time.Now

// RFC008 §3.3: "... A node MUST at least update all CRLs every hour."
// We try to update every hour, no guarantee that it succeeds.
const syncInterval = time.Hour

// After how long a CRL download attempt is stopped.
// Must be short-ish since the update can happen during a validation request.
const syncTimeout = 10 * time.Second

// errors
var (
	ErrCRLMissing    = errors.New("crl is missing")
	ErrCRLExpired    = errors.New("crl has expired")
	ErrCertRevoked   = errors.New("certificate is revoked")
	ErrCertUntrusted = errors.New("certificate's issuer is not trusted'")
)

type Validator interface {
	// Start downloading CRLs. Cancelling the context will stop the Validator.
	Start(ctx context.Context)

	// Validate returns an error if any of the certificates in the chain has been revoked, or if the request cannot be processed.
	// ErrCertRevoked and ErrCertUntrusted indicate that at least one of the certificates is revoked, or signed by a CA that is not in the truststore.
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

	// denylist implements blocking of certificates with tuples of issuer/serial number
	denylist Denylist

	// maxUpdateFailHours is the maximum number of hours that a CRL or denylist can fail to update without causing errors
	maxUpdateFailHours int
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

// New returns a new PKI (crl/denylist) validator.
func NewValidator(config pkiconfig.Config, truststore []*x509.Certificate) (Validator, error) {
	return newValidatorWithHTTPClient(config, truststore, &http.Client{Timeout: syncTimeout})
}

// NewValidatorWithHTTPClient returns a new instance with a pre-configured HTTP client
func newValidatorWithHTTPClient(config pkiconfig.Config, certificates []*x509.Certificate, client *http.Client) (*validator, error) {
	// Create the new denylist with the config
	denylist, err := NewDenylist(config.Denylist)
	if err != nil {
		return nil, fmt.Errorf("failed to init denylist: %w", err)
	}

	// Create the validator
	val := &validator{
		httpClient:         client,
		truststore:         map[string]*x509.Certificate{},
		denylist:           denylist,
		maxUpdateFailHours: config.MaxUpdateFailHours,
	}

	// add truststore
	for _, certificate := range certificates {
		val.truststore[certificate.Subject.String()] = certificate
	}

	// add CRL distribution points
	for _, certificate := range val.truststore {
		issuer, ok := val.truststore[certificate.Issuer.String()]
		if !ok {
			// should never happen, truststore is already validated.
			return nil, fmt.Errorf("certificate's issuer is not in the trust store: subject=%s, issuer=%s", certificate.Subject.String(), certificate.Issuer.String())
		}
		err := val.addEndpoints(issuer, certificate.CRLDistributionPoints)
		if err != nil {
			// should never happen for certificates issued by real CAs
			return nil, err
		}
	}
	return val, nil
}

func (v *validator) Start(ctx context.Context) {
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
				return fmt.Errorf("tls.Config contains certificate with invalid signature: subject=%s", cert.Subject.String())
			}
			// add any previously unknown CRL distribution points.
			// (Leaf cert is likely to contain CRLDistributionPoints not found in the truststore.)
			if err = v.addEndpoints(issuer, cert.CRLDistributionPoints); err != nil {
				return err
			}
		}
	}

	config.VerifyPeerCertificate = func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
		// rawCerts contains raw certificate data presented by the peer during the tls handshake.
		// It is used together with the tls.Config to generate verifiedChains, but may contain additional certs that are not in a verified chain.
		// We reject a client if it sends ANY invalid certificate, even if it is not part of a verifiedChain.
		// This prevents attackers from sending a bunch of certificates hoping one makes it into a verified chain.

		certificates, err := parseCertificatesSlice(rawCerts)
		if err != nil {
			return err
		}

		return v.Validate(certificates)
	}
	return nil
}

func (v *validator) validateCert(cert *x509.Certificate) error {
	// Check if a deneylist is in use
	if v.denylist != nil {
		// Validate the cert against the denylist
		if err := v.denylist.ValidateCert(cert); err != nil {
			// Return any denylist error, blocking the certificate
			return err
		}
	}

	// validate the cert against the CRLs
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
				logger().WithError(err).
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
				logger().WithError(err).
					WithField("Subject", cert.Subject.String()).
					WithField("S/N", cert.SerialNumber.String()).
					WithField("endpoint", endpoint).
					Warn("certificate validation failed because CRL cannot be updated")
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
	// Use a WaitGroup to track when background goroutines are complete
	wg := &sync.WaitGroup{}

	// Check if a denylist is in use
	if v.denylist != nil {
		// Track that a goroutine is being started
		wg.Add(1)

		// Update the denylist in a background routine
		go func() {
			// Ensure that the WaitGroup is updated when this goroutine ends
			defer wg.Done()

			// Update the denylist
			if err := v.denylist.Update(); err != nil {
				// If the denylist is more than X hours out of date then there is a serious issue
				if time.Since(v.denylist.LastUpdated()) > time.Duration(v.maxUpdateFailHours)*time.Hour {
					// Log a message about the failed denylist update
					logger().
						WithError(err).
						WithField("URL", v.denylist.URL()).
						Error("Failed to update denylist")
				} else {
					// Log a message about the failed denylist update
					logger().
						WithError(err).
						WithField("URL", v.denylist.URL()).
						Warn("Failed to update denylist")
				}
			}
		}()
	}

	// Update in parallel if at least one of the issuers is still valid
	v.crls.Range(func(endpointAny, currentAny any) bool {
		// Convert the untyped variables
		endpoint, isString := endpointAny.(string)
		current, isCRL := currentAny.(*revocationList)

		// Ensure the type converions succeeded
		if !isString || !isCRL {
			// This should never happen. If it does, it indicates a programming error in which
			// the v.crls sync.Map has been incorrectly populated.
			logger().
				WithField("endpoint", fmt.Sprintf("%v", endpointAny)).
				WithField("CRL", fmt.Sprintf("%v", currentAny)).
				Error("CRL validator is invalid")

			// Return true in order to continue the range operation
			return true
		}

		// Enforce the certificate NotBefore/NotAfter fields
		if nowFunc().Before(current.issuer.NotBefore) || nowFunc().After(current.issuer.NotAfter) {
			// Log the failure, noting the certificate details in the log message
			logger().
				WithField("subject", current.issuer.Subject.String()).
				WithField("S/N", current.issuer.SerialNumber.String()).
				Warn("Trust store contains expired certificate")

			// Return true in order to continue the range operation
			return true
		}

		// Track that a go routine is being started
		wg.Add(1)
		go func(endpoint string, crl *revocationList, wg *sync.WaitGroup) {
			// Ensure that the waitgroup is updated when this goroutine ends
			defer wg.Done()

			// Retrieve and process the CRL for this endpoint
			err := v.updateCRL(endpoint, crl)
			if err != nil {
				// Connections containing a certificate pointing to this CRL will be accepted until its current.list.NextUpdate.
				if crl != nil || time.Since(crl.lastUpdated) > time.Duration(v.maxUpdateFailHours)*time.Hour {
					// Escalate to error logging if the CRL is missing or fails to update for several hours.
					logger().WithError(err).WithField("CRLDistributionPoint", endpoint).Error("Update CRL")
				} else {
					logger().WithError(err).WithField("CRLDistributionPoint", endpoint).Debug("Update CRL")
				}
			}
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
			logger().Warn(err)
		}
	}()

	data, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, fmt.Errorf("reading CRL response: %w", err)
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

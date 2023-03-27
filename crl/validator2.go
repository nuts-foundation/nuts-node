package crl

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
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

type Validator interface {
	// Start the Validator. Cancelling the context will stop the Validator.
	Start(ctx context.Context)
	// IsRevoked returns true if the certificate has been revoked
	// false + err!=nil when then revocation could not be checked (for soft-fail)
	// false + err==nil if the cert is not revoked
	// Must be called after Start.
	IsRevoked(certificate *x509.Certificate) (bool, error)
	// SetValidatePeerCertificateFunc sets config.ValidatePeerCertificate and MUST be called before Start.
	// Returns an error when config.Certificates contain certificates cannot be parsed,
	// or are signed by CAs that are not int the Validator's truststore.
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
	// crlChan protects crls from race conditions.
	// All operations on crls should be in the func sent to the channel.
	crlChan chan func(result chan interface{})
	// crls maps CRL endpoints to their x509.RevocationList
	crls map[string]*revocationList
}

type revocationList struct {
	// list is the actual revocationList
	list *x509.RevocationList
	// revoked contains all revoked certificated index by their serial number (pkix.RevokedCertificate.SerialNumber.String())
	revoked map[string]*pkix.RevokedCertificate
	// issuers of the CRL found at this endpoint. Multiple issuers could indicate MITM attack, or re-use of endpoint.
	issuers []*x509.Certificate
	// lastUpdated is the timestamp that list was last updated. (When this instance was of revocationList was created)
	lastUpdated time.Time
}

func newRevocationList() *revocationList {
	return &revocationList{
		list:    new(x509.RevocationList),
		revoked: map[string]*pkix.RevokedCertificate{},
		issuers: []*x509.Certificate{},
	}
}

// NewValidator returns a new CRL validator.
func NewValidator(truststore []*x509.Certificate) Validator {
	return newValidatorWithHTTPClient(truststore, http.DefaultClient)
}

// NewValidatorWithHTTPClient returns a new instance with a pre-configured HTTP client
func newValidatorWithHTTPClient(certificates []*x509.Certificate, client *http.Client) Validator {
	certMap := make(map[string]*x509.Certificate, len(certificates))
	listMap := map[string]*revocationList{}

	for _, certificate := range certificates {
		certMap[certificate.Subject.String()] = certificate
		if anyCertificateActive(certificate) { // also logs warning if not active
			for _, endpoint := range certificate.CRLDistributionPoints {
				listMap[endpoint] = newRevocationList()
			}
		}
	}
	return &validator{
		httpClient: client,
		crlChan:    make(chan func(result chan interface{})), // unbuffered
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
	// RFC008 §3.3: "... A node MUST at least update all CRLs every hour."
	// We try to update every hour, no guarantee that it succeeds.
	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()
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
	for {
		select {
		case <-ctx.Done():
			v.started = false
			return
		case f = <-v.crlChan:
			f()
		}
	}
}

func (v *validator) IsRevoked(certificate *x509.Certificate) (bool, error) {
	if !v.started {
		return true, errors.New("CRL validator is not started")
	}
	if err := v.validateChain([]*x509.Certificate{certificate}); err != nil {
		return strings.HasPrefix(err.Error(), "certificate is revoked"), err
	}
	return false, nil
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
			if v.truststore[cert.Issuer.String()] == nil {
				// TODO: this indicates a mismatch between crlValidator truststore and tls.Config. Should this return an error or do we add the CAs from the tls.Config to the validator.
				return errors.New("tls.Config contains certificate from issuer that is not in the truststore: " + cert.Subject.String())
			}
			// add any previously unknown CRL distribution points.
			// (Leaf cert is likely to contain CRLDistributionPoints not found in the truststore.)
			if len(cert.CRLDistributionPoints) > 0 {
				for _, endpoint := range cert.CRLDistributionPoints {
					if v.crls[endpoint] != nil {
						v.crls[endpoint] = newRevocationList()
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

		return v.validateChain(certificates)
	}
	return nil
}

// validateChain validates that none of the certificates in the chain is revoked.
// Certificated in chain are assumed ordered from leaf to root certificate.
func (v *validator) validateChain(chain []*x509.Certificate) error {
	result := make(chan error)
	v.crlChan <- func(result chan interface{}) {
		defer close(result)
		var cert *x509.Certificate
		for i := range chain {
			// check in reverse order to prevent CRL expiration errors due to revoked CAs no longer issuing CRLs
			cert = chain[len(chain)-1-i]
			for _, endpoint := range cert.CRLDistributionPoints {
				crl, ok := v.crls[endpoint]
				// revocation takes precedence over an internal error.
				if ok && crl.revoked[cert.SerialNumber.String()] != nil {
					result <- fmt.Errorf("certificate is revoked: Subject=%s, SN=%s", cert.Subject.String(), cert.SerialNumber.String())
					return
				}
				if !ok || !nowFunc().Before(crl.list.NextUpdate) { // CA expiration is checked earlier in the chain
					if !ok {
						//
						go v.updateCRL(endpoint, nil)
					}
					result <- fmt.Errorf("CRL is missing or expired: Subject=%s, SN=%s", cert.Subject.String(), cert.SerialNumber.String())
					return
				}
			}
		}
		result <- nil
	}
	return <-result
}

// getCRLs returns a copy of the crls map.
// The returned revocationList must not be updated, use setCRL for this.
func (v *validator) getCRLs() map[string]*revocationList {
	result := make(chan map[string]*revocationList)
	v.crlChan <- func(result chan interface{}) {
		defer close(result)
		cp := make(map[string]*revocationList, len(v.crls))
		for ep, crl := range v.crls {
			cp[ep] = crl
		}
		result <- cp
	}
	return <-result
}

// setCRL updates crls in a save way
func (v *validator) setCRL(endpoint string, crl *revocationList) {
	result := make(chan struct{})
	v.crlChan <- func(result chan interface{}) {
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

		go func(ep string, rl *revocationList, wg *sync.WaitGroup) {
			v.updateCRL(ep, rl)
			wg.Done()
		}(endpoint, current, wg)
	}

	wg.Wait()
}

// updateCRL downloads the CRL from endpoint, and updates the revocationList in crls if it is newer than current
func (v *validator) updateCRL(endpoint string, current *revocationList) {
	// download CRL
	crl, err := v.downloadCRL(endpoint)
	if err != nil {
		// Connections containing a certificate pointing to this CRL will be accepted until its current.list.NextUpdate.
		if current != nil && time.Since(current.lastUpdated) > 24*time.Hour {
			// Escalate to error logging if the CRL has not been updated in a day.
			log.Logger().WithError(err).WithField("CRLDistributionPoint", endpoint).Error("Update CRL")
		} else {
			log.Logger().WithError(err).WithField("CRLDistributionPoint", endpoint).Debug("Update CRL")
		}
		return
	}

	// verify signature
	if err = v.verifyCRL(crl); err != nil {
		log.Logger().WithError(err).WithField("CRLDistributionPoint", endpoint).Error("Update CRL")
		return
	}

	// update when it is a new clr
	if current == nil || current.list.Number.Cmp(crl.Number) < 0 {
		// parse revocations
		revoked := make(map[string]*pkix.RevokedCertificate, len(crl.RevokedCertificates))
		for _, rev := range crl.RevokedCertificates {
			revoked[rev.SerialNumber.String()] = &rev
		}
		// update issuers of CRL
		issuers := []*x509.Certificate{}
		if current != nil {
			copy(issuers, current.issuers)
		}
		isNew := true
		for _, iss := range issuers {
			if iss.Issuer.String() == crl.Issuer.String() {
				isNew = false
				break
			}
		}
		if isNew {
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
}

// downloadCRL downloads and parses the CRL
func (v *validator) downloadCRL(endpoint string) (*x509.RevocationList, error) {
	response, err := v.httpClient.Get(endpoint)
	if err != nil {
		return nil, fmt.Errorf("download CRL: %w", err)
	}
	defer func() {
		if err = response.Body.Close(); err != nil {
			log.Logger().Warn(err)
		}
	}()

	data, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, fmt.Errorf("download CRL: %w", err)
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
	return crl.CheckSignatureFrom(certificate)
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

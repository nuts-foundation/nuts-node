package crl

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"io/ioutil"
	"math"
	"math/big"
	"net/http"
	"sync"
	"time"

	"github.com/spaolacci/murmur3"
)

// DB synchronizes CRLs and validates revoked certificates
type DB interface {
	Sync() error
	IsValid(maxOffsetDays int) bool
	Configure(config *tls.Config, maxValidityDays int)
	IsRevoked(issuer string, serialNumber *big.Int) bool
}

type dbImpl struct {
	bitSet           *BitSet
	httpClient       *http.Client
	certificatesLock sync.RWMutex
	listsLock        sync.RWMutex
	certificates     map[string]*x509.Certificate
	lists            map[string]*pkix.CertificateList
}

// NewDB returns a new instance of the CRL database
func NewDB(bitSetSize int, certificates []*x509.Certificate) DB {
	return NewDBWithHTTPClient(bitSetSize, certificates, http.DefaultClient)
}

// NewDBWithHTTPClient returns a new instance with a pre-configured HTTP client
func NewDBWithHTTPClient(bitSetSize int, certificates []*x509.Certificate, httpClient *http.Client) DB {
	certMap := map[string]*x509.Certificate{}

	for _, certificate := range certificates {
		certMap[certificate.Subject.String()] = certificate
	}

	return &dbImpl{
		httpClient:   httpClient,
		bitSet:       NewBitSet(bitSetSize),
		certificates: certMap,
		lists:        map[string]*pkix.CertificateList{},
	}
}

func (db *dbImpl) setRevoked(issuer string, serialNumber *big.Int) {
	bitNum := db.hash(issuer, serialNumber) % int64(db.bitSet.Len())

	db.bitSet.Set(bitNum)
}

func (db *dbImpl) hash(issuer string, serialNumber *big.Int) int64 {
	data := append([]byte(issuer), serialNumber.Bytes()...)
	hash := int64(murmur3.Sum64(data))

	return int64(math.Abs(float64(hash)))
}

// IsRevoked checks whether the certificate was revoked or not
func (db *dbImpl) IsRevoked(issuer string, serialNumber *big.Int) bool {
	bitNum := db.hash(issuer, serialNumber) % int64(db.bitSet.Len())
	if !db.bitSet.IsSet(bitNum) {
		return false
	}

	db.listsLock.RLock()
	defer db.listsLock.RUnlock()

	for _, list := range db.lists {
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

func (db *dbImpl) updateCRL(endpoint string) error {
	db.listsLock.RLock()
	crl, ok := db.lists[endpoint]
	db.listsLock.RUnlock()

	if !ok || crl.HasExpired(time.Now()) {
		return db.downloadCRL(endpoint)
	}

	return nil
}

func (db *dbImpl) verifyCRL(crl *pkix.CertificateList) error {
	db.certificatesLock.RLock()
	defer db.certificatesLock.RUnlock()

	issuerName := crl.TBSCertList.Issuer.String()

	certificate, ok := db.certificates[issuerName]
	if !ok {
		return errors.New("CRL signature could not be validated against known certificates")
	}

	return certificate.CheckCRLSignature(crl)
}

func (db *dbImpl) downloadCRL(endpoint string) error {
	response, err := db.httpClient.Get(endpoint)
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

	if err := db.verifyCRL(crl); err != nil {
		return err
	}

	db.listsLock.Lock()
	defer db.listsLock.Unlock()

	issuerName := crl.TBSCertList.Issuer.String()

	for _, cert := range crl.TBSCertList.RevokedCertificates {
		db.setRevoked(issuerName, cert.SerialNumber)
	}

	db.lists[endpoint] = crl

	return nil
}

// IsValid returns whether all the CRLs are downloaded and are not outdated (based on the offset)
func (db *dbImpl) IsValid(maxOffsetDays int) bool {
	endpoints := db.parseCRLEndpoints()

	db.listsLock.RLock()
	defer db.listsLock.RUnlock()

	// Check if all CRLs have been downloaded
	for _, endpoint := range endpoints {
		if _, ok := db.lists[endpoint]; !ok {
			return false
		}
	}

	// Verify that none of the CRLs are outdated
	now := time.Now().Add(time.Duration(-maxOffsetDays) * (time.Hour * 24))

	for _, list := range db.lists {
		if list.HasExpired(now) {
			return false
		}
	}

	return true
}

func (db *dbImpl) appendCertificates(certificates []*x509.Certificate) {
	db.certificatesLock.Lock()
	defer db.certificatesLock.Unlock()

	for _, certificate := range certificates {
		subject := certificate.Subject.String()

		if _, ok := db.certificates[subject]; !ok {
			db.certificates[subject] = certificate
		}
	}
}

// Configure adds a callback to the TLS config to check if the peer certificate was revoked
func (db *dbImpl) Configure(config *tls.Config, maxValidityDays int) {
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

		db.appendCertificates(verifiedCerts)

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
			if db.IsRevoked(certificate.Issuer.String(), certificate.SerialNumber) {
				return fmt.Errorf("certificate is revoked: %s", certificate.Subject.String())
			}
		}

		// If the CRL db is outdated kill the connection
		if !db.IsValid(maxValidityDays) {
			return errors.New("CRL database is outdated, certificate revocation can't be checked")
		}

		return nil
	}
}

func (db *dbImpl) parseCRLEndpoints() (endpoints []string) {
	db.certificatesLock.RLock()
	defer db.certificatesLock.RUnlock()

	for _, certificate := range db.certificates {
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
func (db *dbImpl) Sync() error {
	endpoints := db.parseCRLEndpoints()

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

			if err := db.updateCRL(e); err != nil {
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

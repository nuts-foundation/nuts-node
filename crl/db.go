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
type DB struct {
	bitSet           *BitSet
	httpClient       *http.Client
	certificatesLock sync.RWMutex
	certificates     []*x509.Certificate
	listsLock        sync.RWMutex
	lists            map[string]*pkix.CertificateList
}

// NewDB returns a new instance of the CRL database
func NewDB(bitSetSize int, certificates []*x509.Certificate) *DB {
	return NewDBWithHTTPClient(bitSetSize, certificates, http.DefaultClient)
}

// NewDBWithHTTPClient returns a new instance with a pre-configured HTTP client
func NewDBWithHTTPClient(bitSetSize int, certificates []*x509.Certificate, httpClient *http.Client) *DB {
	return &DB{
		httpClient:   httpClient,
		bitSet:       NewBitSet(bitSetSize),
		certificates: certificates,
		lists:        map[string]*pkix.CertificateList{},
	}
}

func (db *DB) setRevoked(issuer string, serialNumber *big.Int) {
	bitNum := db.hash(issuer, serialNumber) % int64(db.bitSet.Len())

	db.bitSet.Set(bitNum)
}

func (db *DB) hash(issuer string, serialNumber *big.Int) int64 {
	data := append([]byte(issuer), serialNumber.Bytes()...)
	hash := int64(murmur3.Sum64(data))

	return int64(math.Abs(float64(hash)))
}

// IsRevoked checks whether the certificate was revoked or not
func (db *DB) IsRevoked(issuer string, serialNumber *big.Int) bool {
	bitNum := db.hash(issuer, serialNumber) % int64(db.bitSet.Len())
	if !db.bitSet.IsSet(bitNum) {
		return false
	}

	db.listsLock.RLock()
	defer db.listsLock.RUnlock()

	sn := serialNumber.String()

	for _, list := range db.lists {
		listIssuerName := list.TBSCertList.Issuer.String()

		for _, cert := range list.TBSCertList.RevokedCertificates {
			if listIssuerName == issuer &&
				cert.SerialNumber.String() == sn {
				return true
			}
		}
	}

	return false
}

func (db *DB) updateCRL(endpoint string) error {
	db.listsLock.RLock()
	crl, ok := db.lists[endpoint]
	db.listsLock.RUnlock()

	if !ok || crl.HasExpired(time.Now()) {
		return db.downloadCRL(endpoint)
	}

	return nil
}

func (db *DB) verifyCRL(crl *pkix.CertificateList) error {
	db.certificatesLock.RLock()
	defer db.certificatesLock.RUnlock()

	issuerName := crl.TBSCertList.Issuer.String()

	for _, certificate := range db.certificates {
		if certificate.Subject.String() == issuerName {
			return certificate.CheckCRLSignature(crl)
		}
	}

	return errors.New("CRL signature could not be validated against known certificates")
}

func (db *DB) downloadCRL(endpoint string) error {
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
func (db *DB) IsValid(maxOffsetDays int) bool {
	db.listsLock.RLock()
	defer db.listsLock.RUnlock()

	now := time.Now().Add(time.Duration(-maxOffsetDays) * (time.Hour * 24))

	for _, list := range db.lists {
		if list.HasExpired(now) {
			return false
		}
	}

	return true
}

func (db *DB) appendCertificates(certificates []*x509.Certificate) {
	db.certificatesLock.Lock()
	defer db.certificatesLock.Unlock()

importLoop:
	for _, certificate := range certificates {
		subject := certificate.Subject.String()

		for _, dbCertificate := range db.certificates {
			if dbCertificate.Subject.String() == subject {
				continue importLoop
			}
		}

		db.certificates = append(db.certificates, certificate)
	}
}

// Configure adds a callback to the TLS config to check if the peer certificate was revoked
func (db *DB) Configure(config *tls.Config) {
	verifyPeerCertificate := config.VerifyPeerCertificate

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

		// If the CRL db is outdated kill the connection
		if !db.IsValid(0) {
			return errors.New("CRL database is outdated, certificate revocation can't be checked")
		}

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

		if verifyPeerCertificate != nil {
			return verifyPeerCertificate(rawCerts, verifiedChains)
		}

		return nil
	}
}

func (db *DB) parseCRLEndpoints() (endpoints []string) {
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
func (db *DB) Sync() error {
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

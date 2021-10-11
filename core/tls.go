package core

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"github.com/sirupsen/logrus"
	"github.com/spaolacci/murmur3"
	"io/ioutil"
	"math"
	"math/big"
	"net/http"
	"os"
	"sync"
	"time"
)

func parseCertificates(data []byte) (certificates []*x509.Certificate, _ error) {
	for len(data) > 0 {
		var block *pem.Block

		block, data = pem.Decode(data)
		if block == nil {
			return nil, fmt.Errorf("unable to decode PEM encoded data")
		}

		if block.Type != "CERTIFICATE" {
			continue
		}

		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("unable to parse certificate: %w", err)
		}

		certificates = append(certificates, certificate)
	}

	return
}

type TrustStore struct {
	CertPool     *x509.CertPool
	CRLEndpoints []string
}

// LoadTrustStore creates a x509 certificate pool based on a truststore file
func LoadTrustStore(trustStoreFile string) (*TrustStore, error) {
	data, err := os.ReadFile(trustStoreFile)
	if err != nil {
		return nil, fmt.Errorf("unable to read trust store (file=%s): %w", trustStoreFile, err)
	}

	certificates, err := parseCertificates(data)
	if err != nil {
		return nil, err
	}

	var (
		crlEndpoints []string
		certPool     = x509.NewCertPool()
	)

	for _, certificate := range certificates {
		crlEndpoints = append(crlEndpoints, certificate.CRLDistributionPoints...)

		certPool.AddCert(certificate)
	}

	return &TrustStore{
		CertPool:     certPool,
		CRLEndpoints: crlEndpoints,
	}, nil
}

type RevokedCertificateDB struct {
	bitset    []bool
	endpoints []string
	lists     map[string]*pkix.CertificateList
	lock      sync.RWMutex
}

func NewRevokedCertificateDB(bitsetSize int, endpoints []string) *RevokedCertificateDB {
	return &RevokedCertificateDB{
		bitset:    make([]bool, bitsetSize),
		endpoints: endpoints,
		lists:     map[string]*pkix.CertificateList{},
	}
}

func (db *RevokedCertificateDB) setRevoked(serialNumber *big.Int) {
	bitNum := db.hash(serialNumber) % len(db.bitset)

	db.bitset[bitNum] = true
}

func (db *RevokedCertificateDB) hash(serialNumber *big.Int) int {
	hash := int(murmur3.Sum64(serialNumber.Bytes()))

	return int(math.Abs(float64(hash)))
}

func (db *RevokedCertificateDB) IsRevoked(serialNumber *big.Int) bool {
	bitNum := db.hash(serialNumber) % len(db.bitset)
	if !db.bitset[bitNum] {
		return false
	}

	db.lock.RLock()
	defer db.lock.RUnlock()

	for _, list := range db.lists {
		for _, cert := range list.TBSCertList.RevokedCertificates {
			if cert.SerialNumber.String() == serialNumber.String() {
				return true
			}
		}
	}

	return false
}

func (db *RevokedCertificateDB) updateCRL(endpoint string) error {
	db.lock.RLock()
	crl, ok := db.lists[endpoint]
	db.lock.RUnlock()

	if !ok || crl.HasExpired(time.Now()) {
		return db.downloadCRL(endpoint)
	}

	return nil
}

func (db *RevokedCertificateDB) downloadCRL(endpoint string) error {
	response, err := http.DefaultClient.Get(endpoint)
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

	db.lock.Lock()
	defer db.lock.Unlock()

	for _, cert := range crl.TBSCertList.RevokedCertificates {
		db.setRevoked(cert.SerialNumber)
	}

	db.lists[endpoint] = crl

	return nil
}

func (db *RevokedCertificateDB) Sync() {
	wc := sync.WaitGroup{}
	wc.Add(len(db.endpoints))

	for _, endpoint := range db.endpoints {
		go func(ep string) {
			defer wc.Done()

			if err := db.updateCRL(ep); err != nil {
				logrus.Errorf("failed to download CRL for '%s': %#v", ep, err)
			}
		}(endpoint)
	}

	wc.Wait()
}

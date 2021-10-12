package crl

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"github.com/sirupsen/logrus"
	"github.com/spaolacci/murmur3"
	"io/ioutil"
	"math"
	"math/big"
	"net/http"
	"sync"
	"time"
)

type DB struct {
	bitSet       *BitSet
	certificates []*x509.Certificate
	lists        map[string]*pkix.CertificateList
	lock         sync.RWMutex
}

func NewDB(bitSetSize int, certificates []*x509.Certificate) *DB {
	return &DB{
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

func (db *DB) IsRevoked(issuer string, serialNumber *big.Int) bool {
	bitNum := db.hash(issuer, serialNumber) % int64(db.bitSet.Len())
	if !db.bitSet.IsSet(bitNum) {
		return false
	}

	db.lock.RLock()
	defer db.lock.RUnlock()

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
	db.lock.RLock()
	crl, ok := db.lists[endpoint]
	db.lock.RUnlock()

	if !ok || crl.HasExpired(time.Now()) {
		return db.downloadCRL(endpoint)
	}

	return nil
}

func (db *DB) verifyCRL(crl *pkix.CertificateList) error {
	issuerName := crl.TBSCertList.Issuer.String()

	for _, certificate := range db.certificates {
		if certificate.Subject.String() == issuerName {
			return certificate.CheckCRLSignature(crl)
		}
	}

	return errors.New("CRL signature could not be validated against known certificates")
}

func (db *DB) downloadCRL(endpoint string) error {
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

	if err := db.verifyCRL(crl); err != nil {
		return err
	}

	db.lock.Lock()
	defer db.lock.Unlock()

	issuerName := crl.TBSCertList.Issuer.String()

	for _, cert := range crl.TBSCertList.RevokedCertificates {
		db.setRevoked(issuerName, cert.SerialNumber)
	}

	db.lists[endpoint] = crl

	return nil
}

func (db *DB) Sync() {
	var endpoints []string

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

	wc := sync.WaitGroup{}
	wc.Add(len(endpoints))

	for _, endpoint := range endpoints {
		go func(e string) {
			defer wc.Done()

			if err := db.updateCRL(e); err != nil {
				logrus.Errorf("failed to download CRL for '%s': %#v", e, err)
			}
		}(endpoint)
	}

	wc.Wait()
}

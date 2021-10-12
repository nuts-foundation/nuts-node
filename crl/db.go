package crl

import (
	"crypto/x509"
	"crypto/x509/pkix"
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
	bitSet    *BitSet
	endpoints []string
	lists     map[string]*pkix.CertificateList
	lock      sync.RWMutex
}

func NewDB(bitSetSize int, endpoints []string) *DB {
	return &DB{
		bitSet:    NewBitSet(bitSetSize),
		endpoints: endpoints,
		lists:     map[string]*pkix.CertificateList{},
	}
}

func (db *DB) setRevoked(serialNumber *big.Int) {
	bitNum := db.hash(serialNumber) % db.bitSet.Len()

	db.bitSet.Set(bitNum)
}

func (db *DB) hash(serialNumber *big.Int) int {
	hash := int(murmur3.Sum64(serialNumber.Bytes()))

	return int(math.Abs(float64(hash)))
}

func (db *DB) IsRevoked(serialNumber *big.Int) bool {
	bitNum := db.hash(serialNumber) % db.bitSet.Len()
	if !db.bitSet.IsSet(bitNum) {
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

func (db *DB) updateCRL(endpoint string) error {
	db.lock.RLock()
	crl, ok := db.lists[endpoint]
	db.lock.RUnlock()

	if !ok || crl.HasExpired(time.Now()) {
		return db.downloadCRL(endpoint)
	}

	return nil
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

	db.lock.Lock()
	defer db.lock.Unlock()

	for _, cert := range crl.TBSCertList.RevokedCertificates {
		db.setRevoked(cert.SerialNumber)
	}

	db.lists[endpoint] = crl

	return nil
}

func (db *DB) Sync() {
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

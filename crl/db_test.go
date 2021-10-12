package crl

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io/ioutil"
	"math/big"
	"net/http"
	"testing"

	"github.com/nuts-foundation/nuts-node/core"

	"github.com/stretchr/testify/assert"
)

const (
	pkiOverheidRootCA   = "../network/test/pkioverheid-server-bundle.pem"
	revokedSerialNumber = "700448342687279468507609366171471963528520738260"
	revokedIssuerName   = "CN=Staat der Nederlanden Domein Server CA 2020,O=Staat der Nederlanden,C=NL"
)

type fakeTransport struct{}

func (transport *fakeTransport) RoundTrip(_ *http.Request) (*http.Response, error) {
	return nil, errors.New("random error")
}

func TestDB_Sync(t *testing.T) {
	store, err := core.LoadTrustStore(pkiOverheidRootCA)
	assert.NoError(t, err)

	httpClient := &http.Client{Transport: &fakeTransport{}}

	db := NewDBWithHTTPClient(1000, store.Certificates(), httpClient)

	err = db.Sync()
	assert.Error(t, err)
}

func TestDB_IsRevoked(t *testing.T) {
	sn := new(big.Int)

	if _, ok := sn.SetString(revokedSerialNumber, 10); !ok {
		t.FailNow()
	}

	t.Run("should return true if the certificate was revoked", func(t *testing.T) {
		t.Parallel()

		store, err := core.LoadTrustStore(pkiOverheidRootCA)
		assert.NoError(t, err)

		db := NewDB(1000, store.Certificates())

		err = db.Sync()
		assert.NoError(t, err)

		isRevoked := db.IsRevoked(revokedIssuerName, sn)
		assert.True(t, isRevoked)

		assert.True(t, db.IsValid(0))
	})

	t.Run("should return false if the certificate was not revoked even though the bit was set", func(t *testing.T) {
		t.Parallel()

		store, err := core.LoadTrustStore(pkiOverheidRootCA)
		assert.NoError(t, err)

		db := NewDB(1000, store.Certificates())

		err = db.Sync()
		assert.NoError(t, err)

		db.bitSet = NewBitSet(1)
		db.bitSet.Set(0)

		isRevoked := db.IsRevoked(revokedIssuerName, big.NewInt(100))
		assert.False(t, isRevoked)

		assert.True(t, db.IsValid(0))
	})

	t.Run("should return false when the bit was not set and shouldn't check the actual certificate", func(t *testing.T) {
		t.Parallel()

		store, err := core.LoadTrustStore(pkiOverheidRootCA)
		assert.NoError(t, err)

		db := NewDB(1000, store.Certificates())

		err = db.Sync()
		assert.NoError(t, err)

		db.bitSet = NewBitSet(1)

		isRevoked := db.IsRevoked(revokedIssuerName, sn)
		assert.False(t, isRevoked)
	})
}

func TestDB_Configured(t *testing.T) {
	db := NewDB(1, []*x509.Certificate{})

	config := &tls.Config{}
	db.Configure(config)

	assert.NotNil(t, config.VerifyPeerCertificate)

	data, err := ioutil.ReadFile(pkiOverheidRootCA)
	assert.NoError(t, err)

	block, _ := pem.Decode(data)

	err = config.VerifyPeerCertificate([][]byte{
		block.Bytes,
	}, nil)
	assert.NoError(t, err)
}

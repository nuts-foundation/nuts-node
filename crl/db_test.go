package crl

import (
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/stretchr/testify/assert"
	"math/big"
	"testing"
)

const (
	pkiOverheidRootCA   = "../network/test/pkioverheid-server-bundle.pem"
	revokedSerialNumber = "700448342687279468507609366171471963528520738260"
	revokedIssuerName   = "CN=Staat der Nederlanden Domein Server CA 2020,O=Staat der Nederlanden,C=NL"
)

func TestDB_IsRevoked(t *testing.T) {
	sn := new(big.Int)

	if _, ok := sn.SetString(revokedSerialNumber, 10); !ok {
		t.FailNow()
	}

	store, err := core.LoadTrustStore(pkiOverheidRootCA)
	assert.NoError(t, err)

	revocationDB := NewDB(1000, store.Certificates())
	revocationDB.Sync()

	isRevoked := revocationDB.IsRevoked(revokedIssuerName, sn)
	assert.True(t, isRevoked)
}

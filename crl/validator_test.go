/*
 * Copyright (C) 2021 Nuts community
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

	crlValidator := NewValidatorWithHTTPClient(store.Certificates(), httpClient)

	err = crlValidator.Sync()
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

		crlValidator := NewValidator(store.Certificates())

		err = crlValidator.Sync()
		assert.NoError(t, err)

		isRevoked := crlValidator.IsRevoked(revokedIssuerName, sn)
		assert.True(t, isRevoked)

		assert.True(t, crlValidator.IsSynced(0))
	})

	t.Run("should return false if the certificate was not revoked even though the bit was set", func(t *testing.T) {
		t.Parallel()

		store, err := core.LoadTrustStore(pkiOverheidRootCA)
		assert.NoError(t, err)

		crlValidator := NewValidator(store.Certificates()).(*validator)

		err = crlValidator.Sync()
		assert.NoError(t, err)

		crlValidator.bitSet = NewBitSet(1)
		crlValidator.bitSet.Set(0)

		isRevoked := crlValidator.IsRevoked(revokedIssuerName, big.NewInt(100))
		assert.False(t, isRevoked)

		assert.True(t, crlValidator.IsSynced(0))
	})

	t.Run("should return false when the bit was not set and shouldn't check the actual certificate", func(t *testing.T) {
		t.Parallel()

		store, err := core.LoadTrustStore(pkiOverheidRootCA)
		assert.NoError(t, err)

		crlValidator := NewValidator(store.Certificates()).(*validator)

		err = crlValidator.Sync()
		assert.NoError(t, err)

		crlValidator.bitSet = NewBitSet(1)

		isRevoked := crlValidator.IsRevoked(revokedIssuerName, sn)
		assert.False(t, isRevoked)
	})
}

func TestDB_Configured(t *testing.T) {
	crlValidator := NewValidator([]*x509.Certificate{}).(*validator)
	crlValidator.bitSet = NewBitSet(1)

	config := &tls.Config{}
	crlValidator.Configure(config, 0)

	assert.NotNil(t, config.VerifyPeerCertificate)

	data, err := ioutil.ReadFile(pkiOverheidRootCA)
	assert.NoError(t, err)

	block, _ := pem.Decode(data)

	err = config.VerifyPeerCertificate([][]byte{
		block.Bytes,
	}, nil)
	assert.NoError(t, err)
}

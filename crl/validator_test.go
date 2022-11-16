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
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/nuts-foundation/nuts-node/core"

	"github.com/stretchr/testify/assert"
)

const (
	pkiOverheidRootCA   = "../network/test/pkioverheid-server-bundle.pem"
	pkiOverheidCRL      = "../network/test/pkioverheid.crl"
	revokedSerialNumber = "10000026"
	revokedIssuerName   = "CN=Staat der Nederlanden EV Root CA,O=Staat der Nederlanden,C=NL"
)

type fakeTransport struct {
	responseData []byte
}

type readCloser struct {
	data *bytes.Reader
}

func (s readCloser) Read(p []byte) (n int, err error) {
	return s.data.Read(p)
}

func (s readCloser) Close() error {
	return nil
}

func (transport *fakeTransport) RoundTrip(_ *http.Request) (*http.Response, error) {
	if transport.responseData == nil {
		return nil, errors.New("random error")
	}
	return &http.Response{Body: readCloser{data: bytes.NewReader(transport.responseData)}}, nil
}

func TestValidator_downloadCRL(t *testing.T) {
	t.Run("invalid URL", func(t *testing.T) {
		httpClient := &http.Client{Transport: &fakeTransport{}}
		v := NewValidatorWithHTTPClient(nil, httpClient).(*validator)
		err := v.downloadCRL("file:///non-existing")
		if !assert.Error(t, err) {
			return
		}
		assert.Contains(t, err.Error(), "file:///non-existing")
	})
	t.Run("invalid CRL", func(t *testing.T) {
		httpClient := &http.Client{Transport: &fakeTransport{responseData: []byte("Definitely not a CRL")}}
		v := NewValidatorWithHTTPClient(nil, httpClient).(*validator)
		err := v.downloadCRL("URL-to-CRL")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "unable to parse downloaded CRL (url=URL-to-CRL)")
	})
	t.Run("invalid signature", func(t *testing.T) {
		// Create a CRL with an invalid signature (valid issuer cert, but signed with random private key)
		trustStore, _ := core.LoadTrustStore(pkiOverheidRootCA)
		privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		crlWithInvalidSig, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{Number: big.NewInt(1024)}, trustStore.Certificates()[0], privateKey)
		if !assert.NoError(t, err) {
			return
		}

		httpClient := &http.Client{Transport: &fakeTransport{responseData: crlWithInvalidSig}}
		v := NewValidatorWithHTTPClient(nil, httpClient).(*validator)
		err = v.downloadCRL("CRL with invalid signature")
		assert.EqualError(t, err, "CRL verification failed (issuer=CN=Staat der Nederlanden EV Root CA,O=Staat der Nederlanden,C=NL): CRL signature could not be validated against known certificates")
	})
}

func TestValidator_Sync(t *testing.T) {
	store, err := core.LoadTrustStore(pkiOverheidRootCA)
	assert.NoError(t, err)

	httpClient := &http.Client{Transport: &fakeTransport{}}

	crlValidator := NewValidatorWithHTTPClient(store.Certificates(), httpClient)

	err = crlValidator.Sync()
	assert.Error(t, err)
}

func TestValidator_IsRevoked(t *testing.T) {
	sn := new(big.Int)

	if _, ok := sn.SetString(revokedSerialNumber, 10); !ok {
		t.FailNow()
	}

	// overwrite the nowFunc so the CRL is valid
	nowFunc = func() time.Time {
		return time.Date(2021, 12, 1, 0, 0, 0, 0, time.UTC)
	}

	data, err := os.ReadFile(pkiOverheidCRL)
	if !assert.NoError(t, err) {
		return
	}
	httpClient := &http.Client{Transport: &fakeTransport{responseData: data}}

	t.Run("should return true if the certificate was revoked", func(t *testing.T) {
		store, err := core.LoadTrustStore(pkiOverheidRootCA)
		assert.NoError(t, err)

		crlValidator := NewValidatorWithHTTPClient(store.Certificates(), httpClient)

		err = crlValidator.Sync()
		assert.NoError(t, err)

		isRevoked := crlValidator.IsRevoked(revokedIssuerName, sn)
		assert.True(t, isRevoked)

		assert.True(t, crlValidator.IsSynced(0))
	})

	t.Run("should return false if the crl is expired", func(t *testing.T) {
		oldNowFunc := nowFunc
		nowFunc = func() time.Time {
			return time.Date(2022, 12, 1, 0, 0, 0, 0, time.UTC)
		}

		store, err := core.LoadTrustStore(pkiOverheidRootCA)
		assert.NoError(t, err)

		crlValidator := NewValidatorWithHTTPClient(store.Certificates(), httpClient)
		crlValidator.Sync()

		assert.False(t, crlValidator.IsSynced(0))

		nowFunc = oldNowFunc
	})

	t.Run("should return false if the certificate was not revoked even though the bit was set", func(t *testing.T) {
		store, err := core.LoadTrustStore(pkiOverheidRootCA)
		assert.NoError(t, err)

		crlValidator := NewValidatorWithHTTPClient(store.Certificates(), httpClient).(*validator)

		err = crlValidator.Sync()
		assert.NoError(t, err)

		crlValidator.bitSet = NewBitSet(1)
		crlValidator.bitSet.Set(0)

		isRevoked := crlValidator.IsRevoked(revokedIssuerName, big.NewInt(100))
		assert.False(t, isRevoked)

		assert.True(t, crlValidator.IsSynced(0))
	})

	t.Run("should return false when the bit was not set and shouldn't check the actual certificate", func(t *testing.T) {
		store, err := core.LoadTrustStore(pkiOverheidRootCA)
		assert.NoError(t, err)

		crlValidator := NewValidatorWithHTTPClient(store.Certificates(), httpClient).(*validator)

		err = crlValidator.Sync()
		assert.NoError(t, err)

		crlValidator.bitSet = NewBitSet(1)

		isRevoked := crlValidator.IsRevoked(revokedIssuerName, sn)
		assert.False(t, isRevoked)
	})
}

func TestValidator_Configured(t *testing.T) {
	crlValidator := NewValidator([]*x509.Certificate{}).(*validator)
	crlValidator.bitSet = NewBitSet(1)

	config := &tls.Config{}
	crlValidator.Configure(config, 0)

	assert.NotNil(t, config.VerifyPeerCertificate)
	data, err := os.ReadFile(pkiOverheidRootCA)
	assert.NoError(t, err)

	block, _ := pem.Decode(data)

	err = config.VerifyPeerCertificate([][]byte{
		block.Bytes,
	}, nil)
	assert.NoError(t, err)
}

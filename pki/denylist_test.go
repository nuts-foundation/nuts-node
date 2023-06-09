/*
 * Nuts node
 * Copyright (C) 2023 Nuts community
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

package pki

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jws"
)

// Do not use this public key for anything other than unit tests in denylist_test.go
const publicKeyDoNotUse = `-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAXV5Q9uFPslJcUethKWklYHbIh/2rtOrocZ/Jr7rWpYk=
-----END PUBLIC KEY-----`

// Do not use this private key for anything other than unit tests in denylist_test.go
const privateKeyDoNotUse = `-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIMIU940JfXJsaitDRYvNoAyqL7C/qEDjMX9UjzMZblUR
-----END PRIVATE KEY-----`

// Do not use this private key for anything other than unit tests in denylist_test.go
const incorrectPublicKey = `-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAsJK7Ij4k+sv8y2hD36tPp2KqxNCQMs34T3JgTEKugoI=
-----END PUBLIC KEY-----`

// Do not use this certificate for anything other than unit tests in denylist_test.go
const allowedTestCertificate = `-----BEGIN CERTIFICATE-----
MIIEFzCCAv+gAwIBAgIUfNx4xdDQ4xliuwFvQD4UdzzbHuYwDQYJKoZIhvcNAQEL
BQAwgZoxCzAJBgNVBAYTAk5MMRYwFAYDVQQIDA1Ob29yZC1Ib2xsYW5kMRIwEAYD
VQQHDAlBbXN0ZXJkYW0xITAfBgNVBAoMGEludGVybmV0IFdpZGdpdHMgUHR5IEx0
ZDEYMBYGA1UEAwwPd3d3LmV4YW1wbGUuY29tMSIwIAYJKoZIhvcNAQkBFhNleGFt
cGxlQGV4YW1wbGUuY29tMB4XDTIzMDQxMTEyMzgxMloXDTI0MDQxMDEyMzgxMlow
gZoxCzAJBgNVBAYTAk5MMRYwFAYDVQQIDA1Ob29yZC1Ib2xsYW5kMRIwEAYDVQQH
DAlBbXN0ZXJkYW0xITAfBgNVBAoMGEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDEY
MBYGA1UEAwwPd3d3LmV4YW1wbGUuY29tMSIwIAYJKoZIhvcNAQkBFhNleGFtcGxl
QGV4YW1wbGUuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsnPx
011YqutcTg2vZFx/hb7m6t9PX0zqEfVZXkZ44x+Wf9P2c4jXj2xI5fx3Py5YPGAp
OB4k/Q973veQkWb19si47JcsZUWREIbi+MXWPa6WOPt2cwJzuiYjRDcAgNtYAmCX
yWdQWJjRyIz0uenrcOlOoYgHWIi136YNDyjDfx45AB/lvjKElzKFT7pcT74Ey0ne
sRnCCV698oOjKsGyRIab2cTzq1MMlUf1/Krb+wOXGW+aiFWH2R+mC2cwCedDZ2X2
ctzf4MRwHPH7ih+0QkofzrWqBhR1DVnOoTM+ChlBFMeJmaFPzP+LN1K7JL6x/aL/
5H//h4HtExXQbvHhTwIDAQABo1MwUTAdBgNVHQ4EFgQU5OFnzlcJ7LWcYHVf8eou
nobZSdMwHwYDVR0jBBgwFoAU5OFnzlcJ7LWcYHVf8eounobZSdMwDwYDVR0TAQH/
BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAYo9hzTnlQhMN9DGw5EqIdOZVhM8P
nGyyINHNMFVPp7GmzPxzILa4mwhIxPSMEZvw6tw3u4V6tOJ2G7s4bnIapgaGpQaq
MHVmDaOY3gPZr7+LXdfdSCCmCJc67ZJGXHaVW6zs9bIobNtb7Y9gmoRaKMvM0xlt
IuCk/D7T4YyIukhTl75a+gO6lg+yEsX099uoIsiom9MwADBdmDkesVBK3NzWrxqp
MgDuy4gmTq4sf0gckrQphbE5rDLvbG/MZiUUI8ioSrbXGofsOWpR5P/MlcPO8DUo
jDuiDqsepi+J0Y50roqnYMLR839gRKOqZeFwrtVY+JkV2RSBNwAw7nrT+g==
-----END CERTIFICATE-----`

// Do not use this certificate for anything other than unit tests in denylist_test.go
const bannedTestCertificate = `-----BEGIN CERTIFICATE-----
MIIEFzCCAv+gAwIBAgIUPbKsg6pF+FK6d+l4EAxxR3cIixAwDQYJKoZIhvcNAQEL
BQAwgZoxCzAJBgNVBAYTAk5MMRYwFAYDVQQIDA1Ob29yZC1Ib2xsYW5kMRIwEAYD
VQQHDAlBbXN0ZXJkYW0xITAfBgNVBAoMGEludGVybmV0IFdpZGdpdHMgUHR5IEx0
ZDEYMBYGA1UEAwwPd3d3LmV4YW1wbGUuY29tMSIwIAYJKoZIhvcNAQkBFhNleGFt
cGxlQGV4YW1wbGUuY29tMB4XDTIzMDQxMTEyMzkyOFoXDTI0MDQxMDEyMzkyOFow
gZoxCzAJBgNVBAYTAk5MMRYwFAYDVQQIDA1Ob29yZC1Ib2xsYW5kMRIwEAYDVQQH
DAlBbXN0ZXJkYW0xITAfBgNVBAoMGEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDEY
MBYGA1UEAwwPd3d3LmV4YW1wbGUuY29tMSIwIAYJKoZIhvcNAQkBFhNleGFtcGxl
QGV4YW1wbGUuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAl2u7
dZdAOXfwZ/6dvgzs/4i+dCtghK/H5dd4m709OlDyG0tX90fOgL11OAAB0FVnfKcq
PcDOTMNG9RV5VzONua4y0JF6pnVCaPMzHZcHN04sUfc55reFE1de2I2VB+n+4s+m
tb/UQzts6MtZ4L/o+EFxtg7S52alF8vw4IWbgT0GusDTXC4BhQbiClW8QymRtwwl
AJl2lNiX9cNkGbiRnYtcaTFfHGXEY3uQ/fOZbxLUCyR8QRZQOQ/Z4RTO6ihGBb3J
OqIkyFJLDsVswLUs+fOGg+HywnsFJbxuivRQgQRkioRwXxYCU4jIfQdcSt4UakE3
sDawctE/n6Q2R/yjuwIDAQABo1MwUTAdBgNVHQ4EFgQUKoE23RyA7JC7WU4hAs0s
lbVnxKcwHwYDVR0jBBgwFoAUKoE23RyA7JC7WU4hAs0slbVnxKcwDwYDVR0TAQH/
BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAVGd/tr1a8QJZi/zCzQTdtIVi5hpw
0JA5eV2oi0KnrfxjHbXBEajCnbQoSOJBJtfra8qb/odBgAX3+T1yjmIml2zqk6Jq
Hq16aWHlcgRds0KHZvfFMX5xFsiN0yYQcU+fWWqgQEuTFPpetymHTYrWwBERQYJq
8EWmUH6T/aZVR2bYsqLgogLKDUAbJb/a18AqaWu44LIJcDZl9LK8Ufng/24k2Pw0
ZWp2Pn+Rl1zfuYeXfdtMnFHmGPeiXKZB+u5cZbVxbxZ7nOPEVISKEBxXL8+SE311
btg+JeGSqs/aDd7h/Y/62V/IhFqDHuDQ344zPvbQl+dTz/9FQ7USQMz9Fw==
-----END CERTIFICATE-----`

func testDenylist(url, trustedSigner string) (Denylist, error) {
	cfg := DenylistConfig{
		TrustedSigner: trustedSigner,
		URL:           url,
	}
	return NewDenylist(cfg)
}

// Do not use this value outside of denylist_test.go
const bannedCertIssuer = `CN=www.example.com,O=Internet Widgits Pty Ltd,L=Amsterdam,ST=Noord-Holland,C=NL,1.2.840.113549.1.9.1=#0c136578616d706c65406578616d706c652e636f6d`

// Do not use this value outside of denylist_test.go
const bannedCertSerialNumber = `352232997782095055661451877220413401771436182288`

func denylistTestServer(t *testing.T, denylist string) *httptest.Server {
	testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, denylist)
	}))
	t.Cleanup(testServer.Close)

	return testServer
}

func trustedDenylist(t *testing.T) string {
	// Build the denylist contents
	entries := []denylistEntry{
		denylistEntry{
			Issuer:        `FOO`,
			SerialNumber:  `123`,
			JWKThumbprint: `bim`,
			Reason:        `bap`,
		},
		denylistEntry{
			Issuer:        `BAR`,
			SerialNumber:  `456`,
			JWKThumbprint: `bam`,
			Reason:        `bar`,
		},
		denylistEntry{
			Issuer:        ``,
			SerialNumber:  bannedCertSerialNumber,
			JWKThumbprint: `PVOjk-5d4Lb-FGxurW-fNMUv3rYZZBWF3gGaP5s1UVQ`,
			Reason:        `baz1`,
		},
		denylistEntry{
			Issuer:        bannedCertIssuer,
			SerialNumber:  ``,
			JWKThumbprint: ``,
			Reason:        `baz2`,
		},
		denylistEntry{
			Issuer:        bannedCertIssuer,
			SerialNumber:  bannedCertSerialNumber,
			JWKThumbprint: `PVOjk-5d4Lb-FGxurW-fNMUv3rYZZBWF3gGaP5s1UVQ`,
			Reason:        `baz3`,
		},
		denylistEntry{
			Issuer:        bannedCertIssuer + `arst`,
			SerialNumber:  bannedCertSerialNumber,
			JWKThumbprint: `PVOjk-5d4Lb-FGxurW-fNMUv3rYZZBWF3gGaP5s1UVQ`,
			Reason:        `baz3`,
		},
	}

	return encodeDenylist(t, entries)
}

func encodeDenylist(t *testing.T, entries []denylistEntry) string {
	// Encode the denylist as JSON
	payload, err := json.Marshal(&entries)
	require.NoError(t, err)

	// Parse the private key for signing the denylist
	key, err := jwk.ParseKey([]byte(privateKeyDoNotUse), jwk.WithPEM(true))
	require.NoError(t, err)

	// Sign the denylist as a JWS Message
	compactJWS, err := jws.Sign(payload, jwa.EdDSA, key)
	require.NoError(t, err)

	// Return the compact encoded JWS message
	return string(compactJWS)
}

func TestNewDenylist(t *testing.T) {
	t.Run("disabled", func(t *testing.T) {
		// empty DenylistConfig.URL disables the denylist. This should produce no errors.
		denylist, err := NewDenylist(DenylistConfig{})
		require.NoError(t, err)
		assert.NoError(t, denylist.Update())
		assert.NoError(t, denylist.ValidateCert(&x509.Certificate{}))
		assert.Empty(t, denylist.URL())
		assert.True(t, denylist.LastUpdated().IsZero())
	})
	t.Run("invalid key", func(t *testing.T) {
		_, err := NewDenylist(DenylistConfig{
			URL:           "example.com",
			TrustedSigner: "definitely not valid",
		})
		assert.EqualError(t, err, "failed to parse key: failed to parse PEM encoded key: failed to decode PEM data")
	})
}

// TestBackslashNInKey ensures a denylist is correctly downloaded
func TestBackslashNInKey(t *testing.T) {
	// Get the trusted denylist
	denylistJSON := trustedDenylist(t)

	// Setup a denylist server
	testServer := denylistTestServer(t, denylistJSON)

	// Trusted signer as PEM with literal \n sequences instead of newlines
	trustedSigner := `-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAB262IB4Bg7CzZ/kap8gU+16vD9x/mom7WEjIZsBz+LY=\n-----END PUBLIC KEY-----`

	// Use the server in a new denylist
	denylist, err := NewDenylist(DenylistConfig{URL: testServer.URL, TrustedSigner: trustedSigner})
	require.NoError(t, err)
	require.NotNil(t, denylist)

	// Download the denylist data and ensure it is correct
	bytes, err := denylist.(*denylistImpl).download()
	assert.NoError(t, err)
	assert.Equal(t, string(bytes), denylistJSON)
}

// TestDownloadDenylist ensures a denylist is correctly downloaded
func TestDownloadDenylist(t *testing.T) {
	// Get the trusted denylist
	denylistJSON := trustedDenylist(t)

	// Setup a denylist server
	testServer := denylistTestServer(t, denylistJSON)

	// Use the server in a new denylist
	denylist, err := NewDenylist(DenylistConfig{URL: testServer.URL, TrustedSigner: publicKeyDoNotUse})
	require.NoError(t, err)
	require.NotNil(t, denylist)

	// Download the denylist data and ensure it is correct
	bytes, err := denylist.(*denylistImpl).download()
	assert.NoError(t, err)
	assert.Equal(t, string(bytes), denylistJSON)
}

func TestDenylistMissing(t *testing.T) {
	// Parse the private key for signing the denylist
	key, err := jwk.ParseKey([]byte(privateKeyDoNotUse), jwk.WithPEM(true))
	require.NoError(t, err)

	// Sign an invalid denylist as a JWS Message
	payload := []byte("invalid payload")
	compactJWS, err := jws.Sign(payload, jwa.EdDSA, key)
	require.NoError(t, err)

	// Setup a denylist server
	testServer := denylistTestServer(t, string(compactJWS))

	// Use the server in a new denylist
	denylist, err := NewDenylist(DenylistConfig{URL: testServer.URL, TrustedSigner: publicKeyDoNotUse})
	require.NoError(t, err)
	require.NotNil(t, denylist)

	err = denylist.ValidateCert(&x509.Certificate{})
	assert.ErrorIs(t, err, ErrDenylistMissing)
}

// TestUpdateValidDenylist ensures a trusted denylist can be updated
func TestUpdateValidDenylist(t *testing.T) {
	// Get the trusted denylist
	denylistJSON := trustedDenylist(t)

	// Setup a denylist server
	testServer := denylistTestServer(t, denylistJSON)

	// Use the server in a new denylist
	denylist, err := testDenylist(testServer.URL, publicKeyDoNotUse)
	require.NoError(t, err)
	require.NotNil(t, denylist)

	// Ensure the new denylist update time is zero
	assert.True(t, denylist.LastUpdated().IsZero())

	// Update the denylist data and ensure there are no errors
	err = denylist.Update()
	require.NoError(t, err)

	// Ensure the entries are present as expected in the denylist structure
	entriesPtr := denylist.(*denylistImpl).entries.Load()
	require.NotNil(t, entriesPtr)

	// Dereference the entries slice
	entries := *entriesPtr

	// Ensure the length is as expected
	require.Len(t, entries, 6)

	// Ensure the first issuer/serial numbers are as expected
	assert.Equal(t, entries[0].Issuer, `FOO`)
	assert.Equal(t, entries[0].SerialNumber, `123`)

	// Ensure the lastUpdated time was updated
	assert.False(t, denylist.LastUpdated().IsZero())
}

// TestUpdateInvalidDenylistFails ensures an untrusted denylist cannot be updated
func TestUpdateInvalidDenylistFails(t *testing.T) {
	// Get the trusted denylist
	denylistJSON := trustedDenylist(t)

	// Setup a denylist server
	testServer := denylistTestServer(t, denylistJSON)

	// Use the server in a new denylist but with the wrong public key
	denylist, err := testDenylist(testServer.URL, incorrectPublicKey)
	require.NoError(t, err)
	require.NotNil(t, denylist)

	// Update the denylist data and ensure there is an error
	err = denylist.Update()
	require.Error(t, err)

	// Ensure no denylist data was ingested
	require.Nil(t, denylist.(*denylistImpl).entries.Load())
}

// TestValidCertificateAccepted ensures a non-banned certificate is accepted
func TestValidCertificateAccepted(t *testing.T) {
	// Get the trusted denylist
	denylistJSON := trustedDenylist(t)

	// Setup a denylist server
	testServer := denylistTestServer(t, denylistJSON)

	// Use the server in a new denylist
	denylist, err := testDenylist(testServer.URL, publicKeyDoNotUse)
	require.NoError(t, err)
	require.NotNil(t, denylist)

	// Update the denylist data and ensure there are no errors
	err = denylist.Update()
	require.NoError(t, err)

	// Parse the certificate
	block, _ := pem.Decode([]byte(allowedTestCertificate))
	cert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)

	// Check whether the certificate is banned
	err = denylist.ValidateCert(cert)

	// Ensure the returned error was nil, meaning the certificate is not banned
	assert.NoError(t, err)
}

// TestValidCertificateAcceptedEmptyDenyList ensures a non-banned certificate is accepted with an empty deny list
func TestValidCertificateAcceptedEmptyDenyList(t *testing.T) {
	// Get the trusted denylist
	denylistJSON := encodeDenylist(t, nil)

	// Setup a denylist server
	testServer := denylistTestServer(t, denylistJSON)

	// Use the server in a new denylist
	denylist, err := testDenylist(testServer.URL, publicKeyDoNotUse)
	require.NoError(t, err)
	require.NotNil(t, denylist)

	// Update the denylist data and ensure there are no errors
	err = denylist.Update()
	require.NoError(t, err)

	// Parse the certificate
	block, _ := pem.Decode([]byte(allowedTestCertificate))
	cert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)

	// Check whether the certificate is banned
	err = denylist.ValidateCert(cert)

	// Ensure the returned error was nil, meaning the certificate is not banned
	assert.NoError(t, err)
}

// TestDenylistedCertificateBlocked ensures a banned certificate is not accepted
func TestDenylistedCertificateBlocked(t *testing.T) {
	// Get the trusted denylist
	denylistJSON := trustedDenylist(t)

	// Setup a denylist server
	testServer := denylistTestServer(t, denylistJSON)

	// Use the server in a new denylist
	denylist, err := testDenylist(testServer.URL, publicKeyDoNotUse)
	require.NoError(t, err)
	require.NotNil(t, denylist)

	// Update the denylist data and ensure there are no errors
	err = denylist.Update()
	require.NoError(t, err)

	// Parse the certificate
	block, _ := pem.Decode([]byte(bannedTestCertificate))
	cert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)

	// Check whether the certificate is banned
	err = denylist.ValidateCert(cert)

	// Ensure the validation returned an error, meaning the certificate is banned
	assert.Error(t, err)
	assert.Equal(t, fmt.Errorf("%w: %s", ErrCertBanned, "baz3"), err)
}

// TestEmptyFieldsDoNotBlock ensures empty fields in a denylist entry cannot block certificates
func TestEmptyFieldsDoNotBlock(t *testing.T) {
	// Get the trusted denylist
	denylistJSON := trustedDenylist(t)

	// Setup a denylist server
	testServer := denylistTestServer(t, denylistJSON)

	// Use the server in a new denylist
	denylist, err := testDenylist(testServer.URL, publicKeyDoNotUse)
	require.NoError(t, err)
	require.NotNil(t, denylist)

	// Update the denylist data and ensure there are no errors
	err = denylist.Update()
	require.NoError(t, err)

	// Parse the certificate
	block, _ := pem.Decode([]byte(bannedTestCertificate))
	cert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)

	// Check whether the certificate is banned
	err = denylist.ValidateCert(cert)

	// Ensure the validation returned an error, meaning the certificate is banned
	assert.Error(t, err)
	assert.Equal(t, fmt.Errorf("%w: %s", ErrCertBanned, "baz3"), err)
}

// TestRSACertificateJWKThumbprint ensures ceritficate thumbprints are correctly computed
func TestRSACertificateJWKThumbprint(t *testing.T) {
	// Parse the certificate
	block, _ := pem.Decode([]byte(bannedTestCertificate))
	cert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)

	// Check the JWK fingerprint of the cert
	keyID := certKeyJWKThumbprint(cert)
	assert.Equal(t, "PVOjk-5d4Lb-FGxurW-fNMUv3rYZZBWF3gGaP5s1UVQ", keyID)
}

package crl

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

const publicKey = `-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAXV5Q9uFPslJcUethKWklYHbIh/2rtOrocZ/Jr7rWpYk=
-----END PUBLIC KEY-----`
const privateKey = `-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIMIU940JfXJsaitDRYvNoAyqL7C/qEDjMX9UjzMZblUR
-----END PRIVATE KEY-----`
const incorrectPublicKey = `-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAsJK7Ij4k+sv8y2hD36tPp2KqxNCQMs34T3JgTEKugoI=
-----END PUBLIC KEY-----`

const allowedCertificate = `-----BEGIN CERTIFICATE-----
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

const blacklistedCertificate = `-----BEGIN CERTIFICATE-----
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

const blacklistedCertIssuer = `CN=www.example.com,O=Internet Widgits Pty Ltd,L=Amsterdam,ST=Noord-Holland,C=NL,1.2.840.113549.1.9.1=#0c136578616d706c65406578616d706c652e636f6d`
const blacklistedCertSerialNumber = `352232997782095055661451877220413401771436182288`

func blacklistTestServer(blacklist string) *httptest.Server {
	testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, blacklist)
	}))

	return testServer
}

func trustedBlacklist(t *testing.T) string {
	// Build the blacklist contents
	entries := []blacklistEntry{
		blacklistEntry{
			Issuer:       `FOO`,
			SerialNumber: `123`,
		},
		blacklistEntry{
			Issuer:       `BAR`,
			SerialNumber: `456`,
		},
		blacklistEntry{
			Issuer:       blacklistedCertIssuer,
			SerialNumber: blacklistedCertSerialNumber,
		},
	}

	// Encode the blacklist as JSON
	payload, err := json.Marshal(&entries)
	require.NoError(t, err)

	// Parse the private key for signing the blacklist
	key, err := jwk.ParseKey([]byte(privateKey), jwk.WithPEM(true))
	require.NoError(t, err)

	// Sign the blacklist as a JWS Message
	compactJWS, err := jws.Sign(payload, jwa.EdDSA, key)
	require.NoError(t, err)

	// Return the compact encoded JWS message
	return string(compactJWS)
}

// TestDownloadBlacklist ensures a blacklist is correctly downloaded
func TestDownloadBlacklist(t *testing.T) {
	// Get the trusted blacklist
	blacklistJSON := trustedBlacklist(t)

	// Setup a blacklist server
	testServer := blacklistTestServer(blacklistJSON)
	defer testServer.Close()

	// Use the server in a new blacklist
	blacklist, err := newBlacklist(testServer.URL, publicKey)
	require.NoError(t, err)
	require.NotNil(t, blacklist)

	// Download the blacklist data and ensure it is correct
	bytes, err := blacklist.download()
	assert.Equal(t, string(bytes), blacklistJSON)
}

// TestUpdateValidBlacklist ensures a trusted blacklist can be updated
func TestUpdateValidBlacklist(t *testing.T) {
	// Get the trusted blacklist
	blacklistJSON := trustedBlacklist(t)

	// Setup a blacklist server
	testServer := blacklistTestServer(blacklistJSON)
	defer testServer.Close()

	// Use the server in a new blacklist
	blacklist, err := newBlacklist(testServer.URL, publicKey)
	require.NoError(t, err)
	require.NotNil(t, blacklist)

	// Ensure the new blacklist update time is zero
	assert.True(t, blacklist.lastUpdated.IsZero())

	// Update the blacklist data and ensure there are no errors
	err = blacklist.update()
	require.NoError(t, err)

	// Ensure the entries are present as expected in the blacklist structure
	entriesPtr := blacklist.entries.Load()
	require.NotNil(t, entriesPtr)

	// Dereference the entries slice
	entries := *entriesPtr

	// Ensure the length is as expected
	require.Len(t, entries, 3)

	// Ensure the issuers and serial numbers are as expected
	assert.Equal(t, entries[0].Issuer, `FOO`)
	assert.Equal(t, entries[0].SerialNumber, `123`)
	assert.Equal(t, entries[1].Issuer, `BAR`)
	assert.Equal(t, entries[1].SerialNumber, `456`)
	assert.Equal(t, entries[2].Issuer, blacklistedCertIssuer)
	assert.Equal(t, entries[2].SerialNumber, blacklistedCertSerialNumber)

	// Ensure the lastUpdated time was updated
	assert.False(t, blacklist.lastUpdated.IsZero())
}

// TestUpdateInvalidBlacklistFails ensures an untrusted blacklist cannot be updated
func TestUpdateInvalidBlacklistFails(t *testing.T) {
	// Get the trusted blacklist
	blacklistJSON := trustedBlacklist(t)

	// Setup a blacklist server
	testServer := blacklistTestServer(blacklistJSON)
	defer testServer.Close()

	// Use the server in a new blacklist but with the wrong public key
	blacklist, err := newBlacklist(testServer.URL, incorrectPublicKey)
	require.NoError(t, err)
	require.NotNil(t, blacklist)

	// Update the blacklist data and ensure there is an error
	err = blacklist.update()
	require.Error(t, err)

	// Ensure no blacklist data was ingested
	require.Nil(t, blacklist.entries.Load())
}

// TestValidCertificateAccepted ensures a non-blacklisted certificate is accepted
func TestValidCertificateAccepted(t *testing.T) {
	// Get the trusted blacklist
	blacklistJSON := trustedBlacklist(t)

	// Setup a blacklist server
	testServer := blacklistTestServer(blacklistJSON)
	defer testServer.Close()

	// Use the server in a new blacklist
	blacklist, err := newBlacklist(testServer.URL, publicKey)
	require.NoError(t, err)
	require.NotNil(t, blacklist)

	// Update the blacklist data and ensure there are no errors
	err = blacklist.update()
	require.NoError(t, err)

	// Parse the certificate
	block, _ := pem.Decode([]byte(allowedCertificate))
	cert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)

	// Check whether the certificate is blacklisted
	err = blacklist.validateCert(cert)

	// Ensure the returned error was nil, meaning the certificate is not blacklisted
	assert.NoError(t, err)
}

// TestBlacklistedCertificateBlocked ensures a blacklisted certificate is not accepted
func TestBlacklistedCertificateBlocked(t *testing.T) {
	// Get the trusted blacklist
	blacklistJSON := trustedBlacklist(t)

	// Setup a blacklist server
	testServer := blacklistTestServer(blacklistJSON)
	defer testServer.Close()

	// Use the server in a new blacklist
	blacklist, err := newBlacklist(testServer.URL, publicKey)
	require.NoError(t, err)
	require.NotNil(t, blacklist)

	// Update the blacklist data and ensure there are no errors
	err = blacklist.update()
	require.NoError(t, err)

	// Parse the certificate
	block, _ := pem.Decode([]byte(blacklistedCertificate))
	cert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)

	// Check whether the certificate is blacklisted
	err = blacklist.validateCert(cert)

	// Ensure the validation returned an error, meaning the certificate is blacklisted
	assert.Error(t, err)
	assert.Equal(t, err, ErrCertBlacklisted)
}

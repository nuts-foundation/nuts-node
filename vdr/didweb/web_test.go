/*
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

package didweb

import (
	"crypto/tls"
	"github.com/nuts-foundation/go-did/did"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

const didDocTemplate = `
{
  "context": "https://www.w3.org/ns/did/v1",
  "id": "<did>",
  "capabilityInvocation": ["<did>#aQgahRFAhdStcQyD6R25fFYslo4JZXuqYUySTtXB_Lo"],
  "verificationMethod": [
    {
      "controller": "<did>",
      "id": "<did>#aQgahRFAhdStcQyD6R25fFYslo4JZXuqYUySTtXB_Lo",
      "publicKeyJwk": {
        "crv": "P-256",
        "kid": "<did>#aQgahRFAhdStcQyD6R25fFYslo4JZXuqYUySTtXB_Lo",
        "kty": "EC",
        "x": "iCpv6AGDpdYVZjniwklkL8A4DGNhBK/DngbpdDjjBlo=",
        "y": "27/qwElvfxhXtG2TDSO5LwReuFRwR+qydBdpQqu6H5M="
      },
      "type": "JsonWebKey2020"
    }
  ]
}`

func TestResolver_NewResolver(t *testing.T) {
	resolver := NewResolver()
	assert.NotNil(t, resolver.HttpClient)

	t.Run("it sets min TLS version", func(t *testing.T) {
		assert.Equal(t, uint16(tls.VersionTLS12), resolver.HttpClient.Transport.(*http.Transport).TLSClientConfig.MinVersion)
	})
}

func TestResolver_Resolve(t *testing.T) {
	var baseDID did.DID
	tlsServer := httptest.NewUnstartedServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/.well-known/did.json":
			writer.Header().Add("Content-Type", "application/did+json")
			writer.WriteHeader(http.StatusOK)
			_, _ = writer.Write([]byte(strings.ReplaceAll(didDocTemplate, "<did>", baseDID.String())))
			return
		case "/json-ld/did.json":
			writer.Header().Add("Content-Type", "application/did+ld+json")
			writer.WriteHeader(http.StatusOK)
			_, _ = writer.Write([]byte(strings.ReplaceAll(didDocTemplate, "<did>", baseDID.String()+":json-ld")))
			return
		case "/json/did.json":
			writer.Header().Add("Content-Type", "application/json")
			writer.WriteHeader(http.StatusOK)
			_, _ = writer.Write([]byte(strings.ReplaceAll(didDocTemplate, "<did>", baseDID.String()+":json")))
			return
		case "/unsupported-content-type/did.json":
			writer.Header().Add("Content-Type", "text/plain")
			writer.WriteHeader(http.StatusOK)
			_, _ = writer.Write([]byte(strings.ReplaceAll(didDocTemplate, "<did>", baseDID.String())))
			return
		case "/invalid-json/did.json":
			writer.Header().Add("Content-Type", "application/json")
			writer.WriteHeader(http.StatusOK)
			_, _ = writer.Write([]byte{1, 2, 3})
			return
		case "/no-content-type/did.json":
			return
		case "/invalid-id-in-document/did.json":
			writer.Header().Add("Content-Type", "application/did+json")
			writer.WriteHeader(http.StatusOK)
			_, _ = writer.Write([]byte(strings.ReplaceAll(didDocTemplate, "<did>", "did:example:123")))
			return
		default:
			writer.WriteHeader(http.StatusNotFound)
		}
	}))
	keyPair, err := tls.LoadX509KeyPair("../../http/test/cert.pem", "../../http/test/key.pem")
	require.NoError(t, err)
	tlsServer.TLS = &tls.Config{
		Certificates: []tls.Certificate{keyPair},
	}
	tlsServer.StartTLS()
	defer tlsServer.Close()
	resolver := &Resolver{
		HttpClient: tlsServer.Client(),
	}

	tlsServer.URL = strings.ReplaceAll(tlsServer.URL, "127.0.0.1", "localhost")
	baseDIDString := url.QueryEscape(strings.TrimPrefix(tlsServer.URL, "https://"))
	baseDID = did.MustParseDID("did:web:" + baseDIDString)

	t.Run("resolve base DID - content-type=json+did", func(t *testing.T) {
		doc, md, err := resolver.Resolve(baseDID, nil)

		require.NoError(t, err)
		assert.NotNil(t, md)
		require.NotNil(t, doc)
		assert.Equal(t, baseDID, doc.ID)
	})
	t.Run("resolve base DID - content-type=json", func(t *testing.T) {
		doc, md, err := resolver.Resolve(did.MustParseDID(baseDID.String()+":json"), nil)

		assert.NoError(t, err)
		assert.NotNil(t, md)
		assert.NotNil(t, doc)
	})
	t.Run("resolve base DID - content-type=json-ld", func(t *testing.T) {
		doc, md, err := resolver.Resolve(did.MustParseDID(baseDID.String()+":json-ld"), nil)

		assert.NoError(t, err)
		assert.NotNil(t, md)
		assert.NotNil(t, doc)
	})
	t.Run("resolve DID with path", func(t *testing.T) {
		id := did.MustParseDIDURL(baseDID.String() + "/some/path")
		doc, md, err := resolver.Resolve(id, nil)

		require.NoError(t, err)
		assert.NotNil(t, md)
		require.NotNil(t, doc)
		assert.Equal(t, baseDID, doc.ID)
	})

	t.Run("resolve without port number", func(t *testing.T) {
		// The other tests all use a port number, since the test HTTPS server is running on a random port.
		// This test stubs http.Transport to test without a port number.
		didToResolve := did.MustParseDID("did:web:example.com")
		var requestURL string
		httpTransport := roundTripperFunc(func(r *http.Request) (*http.Response, error) {
			requestURL = r.URL.String()
			return &http.Response{
				Header:     map[string][]string{"Content-Type": {"application/json"}},
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader(`{"id": "did:web:example.com"}`)),
			}, nil
		})

		doc, md, err := Resolver{HttpClient: &http.Client{Transport: httpTransport}}.Resolve(didToResolve, nil)

		require.NoError(t, err)
		assert.NotNil(t, md)
		require.NotNil(t, doc)
		assert.Equal(t, "https://example.com/.well-known/did.json", requestURL)
	})
	t.Run("not found", func(t *testing.T) {
		id := did.MustParseDIDURL(baseDID.String() + ":not-found")
		doc, md, err := resolver.Resolve(id, nil)

		assert.EqualError(t, err, "did:web non-ok HTTP status: 404 Not Found")
		assert.Nil(t, md)
		assert.Nil(t, doc)
	})
	t.Run("unsupported content-type", func(t *testing.T) {
		id := did.MustParseDIDURL(baseDID.String() + ":unsupported-content-type")
		doc, md, err := resolver.Resolve(id, nil)

		assert.EqualError(t, err, "did:web unsupported content-type: text/plain")
		assert.Nil(t, md)
		assert.Nil(t, doc)
	})
	t.Run("server returns invalid JSON", func(t *testing.T) {
		id := did.MustParseDIDURL(baseDID.String() + ":invalid-json")
		doc, md, err := resolver.Resolve(id, nil)

		assert.EqualError(t, err, "did:web JSON unmarshal error: invalid character '\\x01' looking for beginning of value")
		assert.Nil(t, md)
		assert.Nil(t, doc)
	})
	t.Run("server returns no content-type", func(t *testing.T) {
		id := did.MustParseDIDURL(baseDID.String() + ":no-content-type")
		doc, md, err := resolver.Resolve(id, nil)

		assert.EqualError(t, err, "did:web invalid content-type: mime: no media type")
		assert.Nil(t, md)
		assert.Nil(t, doc)
	})
	t.Run("ID in document does not match DID being resolved", func(t *testing.T) {
		id := did.MustParseDIDURL(baseDID.String() + ":invalid-id-in-document")
		doc, md, err := resolver.Resolve(id, nil)

		assert.ErrorContains(t, err, "did:web document ID mismatch")
		assert.Nil(t, md)
		assert.Nil(t, doc)
	})
	t.Run("DID validation", func(t *testing.T) {
		t.Run("method isn't did:web", func(t *testing.T) {
			doc, md, err := resolver.Resolve(did.MustParseDID("did:example:123"), nil)

			assert.EqualError(t, err, "DID is not did:web")
			assert.Nil(t, md)
			assert.Nil(t, doc)
		})
		t.Run("contains empty paths (every : must be followed by a path)", func(t *testing.T) {
			doc, md, err := resolver.Resolve(did.MustParseDID("did:web:example.com:sub::path"), nil)

			assert.EqualError(t, err, "invalid did:web: contains empty path elements")
			assert.Nil(t, md)
			assert.Nil(t, doc)
		})
		t.Run("ends with empty path (every : must be followed by a path)", func(t *testing.T) {
			doc, md, err := resolver.Resolve(did.MustParseDID("did:web:example.com:"), nil)

			assert.EqualError(t, err, "invalid did:web: contains empty path elements")
			assert.Nil(t, md)
			assert.Nil(t, doc)
		})
		t.Run("ID must be just domain (contains encoded path)", func(t *testing.T) {
			doc, md, err := resolver.Resolve(did.MustParseDID("did:web:example.com%2Fpath"), nil)

			assert.EqualError(t, err, "invalid did:web: illegal characters in domain name")
			assert.Nil(t, md)
			assert.Nil(t, doc)
		})
		t.Run("ID must be just domain, with port (contains encoded path)", func(t *testing.T) {
			doc, md, err := resolver.Resolve(did.MustParseDID("did:web:example.com%3A443%2Fpath"), nil)

			assert.EqualError(t, err, "invalid did:web: illegal characters in domain name")
			assert.Nil(t, md)
			assert.Nil(t, doc)
		})
		t.Run("ID can't be an IP address (IPv4)", func(t *testing.T) {
			doc, md, err := resolver.Resolve(did.MustParseDID("did:web:127.0.0.1"), nil)

			assert.EqualError(t, err, "invalid did:web: ID must be a domain name, not IP address")
			assert.Nil(t, md)
			assert.Nil(t, doc)
		})
		t.Run("ID can't be an IP address (IPv6)", func(t *testing.T) {
			// did.Parse() rejects IPv6 addresses in DIDs, so we have to "build" it
			doc, md, err := resolver.Resolve(did.DID{
				Method: MethodName,
				ID:     "[%3A%3A1]",
			}, nil)

			assert.EqualError(t, err, "invalid did:web: ID must be a domain name, not IP address")
			assert.Nil(t, md)
			assert.Nil(t, doc)
		})
	})
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (fn roundTripperFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return fn(r)
}

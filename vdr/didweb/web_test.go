package didweb

import (
	"github.com/nuts-foundation/go-did/did"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
}

func TestResolver_Resolve(t *testing.T) {
	var baseDID did.DID
	tlsServer := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
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
	defer tlsServer.Close()
	resolver := &Resolver{
		HttpClient: tlsServer.Client(),
	}

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
	t.Run("method isn't did:web", func(t *testing.T) {
		doc, md, err := resolver.Resolve(did.MustParseDID("did:example:123"), nil)

		assert.EqualError(t, err, "DID is not did:web")
		assert.Nil(t, md)
		assert.Nil(t, doc)
	})
}

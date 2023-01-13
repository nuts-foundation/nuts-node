package storage

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"github.com/nuts-foundation/nuts-node/crypto/storage/httpclient"
	"github.com/nuts-foundation/nuts-node/crypto/util"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

var errResponse = httpclient.ErrorResponse{
	Backend: "vault",
	Detail:  "permission denied",
	Status:  403,
	Title:   "Lookup failed, backend returned and error",
}

func serverWithKey(t *testing.T, key *ecdsa.PrivateKey) *httptest.Server {
	t.Helper()
	pem, _ := util.PrivateKeyToPem(key)

	return httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.Method {
		case http.MethodGet:
			switch request.URL.Path {
			case "/health":
				writer.WriteHeader(http.StatusOK)
				break
			case "/secrets":
				writer.Header().Set("Content-Type", "application/json")
				writer.WriteHeader(http.StatusOK)
				_, _ = writer.Write([]byte(`["test"]`))
				break
			case "/secrets/test":
				writer.Header().Set("Content-Type", "application/json")
				response := httpclient.SecretResponse{Data: pem}
				responseAsJSON, _ := json.Marshal(response)
				writer.WriteHeader(http.StatusOK)
				_, _ = writer.Write(responseAsJSON)
				break
			case "/secrets/bad-request":
				writer.Header().Set("Content-Type", "application/json")
				responseAsJSON, _ := json.Marshal(errResponse)
				writer.WriteHeader(http.StatusBadRequest)
				_, _ = writer.Write(responseAsJSON)
				break
			case "/secrets/invalid-response":
				writer.Header().Set("Content-Type", "application/json")
				writer.WriteHeader(http.StatusOK)
				_, _ = writer.Write([]byte("invalid"))
				break
			case "/secrets/not-pem":
				writer.Header().Set("Content-Type", "application/json")
				response := httpclient.SecretResponse{Data: "not-pem"}
				responseAsJSON, _ := json.Marshal(response)
				writer.WriteHeader(http.StatusOK)
				_, _ = writer.Write(responseAsJSON)
				break
			case "/secrets/not-json":
				writer.Header().Set("Content-Type", "xml")
				writer.WriteHeader(http.StatusOK)
				break
			case "/secrets/bad-request-with-wrong-format":
				writer.Header().Set("Content-Type", "application/json")
				responseAsJSON, _ := json.Marshal("not-a-valid-error-response")
				writer.WriteHeader(http.StatusBadRequest)
				_, _ = writer.Write(responseAsJSON)
				break
			case "/secrets/server-error":
				writer.Header().Set("Content-Type", "application/json")
				writer.WriteHeader(http.StatusInternalServerError)
				break
			default:
				writer.WriteHeader(http.StatusNotFound)
			}
			break
		case http.MethodPost:
			if request.URL.Path == "/secrets/test" {
				body, _ := io.ReadAll(request.Body)
				storeRequest := httpclient.StoreSecretRequest{}
				_ = json.Unmarshal(body, &storeRequest)
				assert.Equal(t, httpclient.StoreSecretRequest{Data: pem}, storeRequest)
				writer.WriteHeader(http.StatusOK)
			} else if request.URL.Path == "/secrets/bad-request" {
				writer.Header().Set("Content-Type", "application/json")
				responseAsJSON, _ := json.Marshal(errResponse)
				writer.WriteHeader(http.StatusBadRequest)
				_, _ = writer.Write(responseAsJSON)
			} else if request.URL.Path == "/secrets/bad-request-with-wrong-format" {
				writer.Header().Set("Content-Type", "application/json")
				responseAsJSON, _ := json.Marshal("not-a-valid-error-response")
				writer.WriteHeader(http.StatusBadRequest)
				_, _ = writer.Write(responseAsJSON)
			} else if request.URL.Path == "/secrets/existing-key" {
				writer.WriteHeader(http.StatusConflict)
			} else if request.URL.Path == "/secrets/server-error" {
				writer.Header().Set("Content-Type", "application/json")
				writer.WriteHeader(http.StatusInternalServerError)
			} else {
				writer.WriteHeader(http.StatusNotFound)
			}
		}
	}))
}

func TestNewAPIClient(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		var key, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		client, err := NewAPIClient(serverWithKey(t, key).URL)
		require.NoError(t, err)
		assert.NotNil(t, client)
	})

	t.Run("invalid url", func(t *testing.T) {
		client, err := NewAPIClient("invalid-url")
		assert.EqualError(t, err, "unable to connect to storage server: Get \"/invalid-url/health\": unsupported protocol scheme \"\"")
		assert.Nil(t, client)
	})

	t.Run("error - service unavailable", func(t *testing.T) {
		s := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			switch request.Method {
			case http.MethodGet:
				switch request.URL.Path {
				case "/health":
					writer.WriteHeader(http.StatusServiceUnavailable)
					break
				}
			}
		}))
		client, err := NewAPIClient(s.URL)
		assert.EqualError(t, err, "unable to connect to storage server: unexpected status code: 503")
		assert.Nil(t, client)
	})
}

func TestAPIClient_GetPrivateKey(t *testing.T) {
	var key, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	s := serverWithKey(t, key)
	t.Run("ok - it should return a private key", func(t *testing.T) {

		client, err := NewAPIClient(s.URL)
		require.NoError(t, err)

		resolvedKey, err := client.GetPrivateKey("test")
		require.NoError(t, err)
		assert.Equal(t, key, resolvedKey)
	})

	t.Run("error - invalid response body", func(t *testing.T) {
		client, err := NewAPIClient(s.URL)
		require.NoError(t, err)

		result, err := client.GetPrivateKey("invalid-response")
		require.EqualError(t, err, "unable to get private-key: invalid character 'i' looking for beginning of value")
		assert.Nil(t, result)
	})

	t.Run("error - value is not in pem format", func(t *testing.T) {
		client, _ := NewAPIClient(s.URL)
		result, err := client.GetPrivateKey("not-pem")
		require.EqualError(t, err, "unable to parse private key as pem: failed to decode PEM block containing private key")
		assert.Nil(t, result)
	})

	t.Run("error - content type is not json", func(t *testing.T) {
		client, _ := NewAPIClient(s.URL)
		result, err := client.GetPrivateKey("not-json")
		require.EqualError(t, err, "unable to get private-key: unexpected content-type: xml")
		assert.Nil(t, result)
	})

	t.Run("error - error response in wrong format", func(t *testing.T) {
		client, _ := NewAPIClient(s.URL)
		result, err := client.GetPrivateKey("bad-request-with-wrong-format")
		require.EqualError(t, err, "unable to get private-key: json: cannot unmarshal string into Go value of type httpclient.ErrorResponse")
		assert.Nil(t, result)
	})

	t.Run("error - key not found", func(t *testing.T) {
		client, _ := NewAPIClient(s.URL)

		resolvedKey, err := client.GetPrivateKey("unknown-key")
		require.EqualError(t, err, errKeyNotFound.Error())
		require.Nil(t, resolvedKey)
	})

	t.Run("error - bad request", func(t *testing.T) {
		client, _ := NewAPIClient(s.URL)

		resolvedKey, err := client.GetPrivateKey("bad-request")
		require.EqualError(t, err, backendError{errResponse}.Error())
		require.Nil(t, resolvedKey)
	})
	t.Run("error - server error", func(t *testing.T) {
		client, _ := NewAPIClient(s.URL)

		resolvedKey, err := client.GetPrivateKey("server-error")
		require.EqualError(t, err, "unable to get private-key: unexpected status code from storage server: 500")
		require.Nil(t, resolvedKey)
	})
}

func TestAPIClient_StorePrivateKey(t *testing.T) {
	var key, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	s := serverWithKey(t, key)

	t.Run("ok - it should store a private key", func(t *testing.T) {
		client, _ := NewAPIClient(s.URL)

		err := client.SavePrivateKey("test", key)
		require.NoError(t, err)
	})

	t.Run("error - key already exists", func(t *testing.T) {
		client, _ := NewAPIClient(s.URL)

		err := client.SavePrivateKey("existing-key", key)
		require.EqualError(t, err, errKeyAlreadyExists.Error())
	})

	t.Run("error - bad request", func(t *testing.T) {
		client, _ := NewAPIClient(s.URL)

		err := client.SavePrivateKey("bad-request", key)
		require.EqualError(t, err, backendError{errResponse}.Error())
	})

	t.Run("error - value is not in pem format", func(t *testing.T) {
		client, _ := NewAPIClient(s.URL)

		err := client.SavePrivateKey("not-pem", []byte("not-pem"))
		require.EqualError(t, err, "unable to convert private key to pem format: x509: unknown key type while marshaling PKCS#8: []uint8")
	})

	t.Run("error - error response in wrong format", func(t *testing.T) {
		client, _ := NewAPIClient(s.URL)

		err := client.SavePrivateKey("bad-request-with-wrong-format", key)
		require.EqualError(t, err, "unable to save private-key: json: cannot unmarshal string into Go value of type httpclient.ErrorResponse")

	})
	t.Run("error - server error", func(t *testing.T) {
		client, _ := NewAPIClient(s.URL)

		err := client.SavePrivateKey("server-error", key)
		require.EqualError(t, err, "unexpected status code from storage server: 500")
	})
}

func TestAPIClient_PrivateKeyExists(t *testing.T) {
	var key, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	s := serverWithKey(t, key)

	t.Run("ok - it should return true if the key exists", func(t *testing.T) {
		client, _ := NewAPIClient(s.URL)

		exists := client.PrivateKeyExists("test")
		require.True(t, exists)
	})

	t.Run("ok - it should return false if the key does not exist", func(t *testing.T) {
		client, _ := NewAPIClient(s.URL)

		exists := client.PrivateKeyExists("unknown-key")
		require.False(t, exists)
	})

	t.Run("error - it returns false if the server returns an error", func(t *testing.T) {
		client, _ := NewAPIClient(s.URL)

		exists := client.PrivateKeyExists("bad-request")
		require.False(t, exists)
	})

	t.Run("error - it returns false if the response has an invalid format", func(t *testing.T) {
		client, _ := NewAPIClient(s.URL)

		exists := client.PrivateKeyExists("invalid-response")
		require.False(t, exists)
	})
}

func TestAPIClient_ListPrivateKeys(t *testing.T) {
	t.Run("ok - it returns an empty list of keys", func(t *testing.T) {
		s := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			switch request.Method {
			case http.MethodGet:
				switch request.URL.Path {
				case "/health":
					writer.WriteHeader(http.StatusOK)
					break
				case "/secrets":
					writer.Header().Set("Content-Type", "application/json")
					writer.WriteHeader(http.StatusOK)
					_, _ = writer.Write([]byte(`[]`))
					break
				}
			}
		}))
		client, err := NewAPIClient(s.URL)
		require.NoError(t, err)
		keys := client.ListPrivateKeys()
		require.Equal(t, []string{}, keys)
	})

	t.Run("ok - it returns a not empty list of keys", func(t *testing.T) {
		s := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			switch request.Method {
			case http.MethodGet:
				switch request.URL.Path {
				case "/health":
					writer.WriteHeader(http.StatusOK)
					break
				case "/secrets":
					writer.Header().Set("Content-Type", "application/json")
					writer.WriteHeader(http.StatusOK)
					_, _ = writer.Write([]byte(`["key1", "key2"]`))
					break
				}
			}
		}))
		client, err := NewAPIClient(s.URL)
		require.NoError(t, err)
		keys := client.ListPrivateKeys()
		require.Equal(t, []string{"key1", "key2"}, keys)
	})

	t.Run("error - it returns an empty list of keys if the server returns an error", func(t *testing.T) {
		s := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			switch request.Method {
			case http.MethodGet:
				switch request.URL.Path {
				case "/health":
					writer.WriteHeader(http.StatusOK)
					break
				case "/secrets":
					writer.Header().Set("Content-Type", "application/json")
					writer.WriteHeader(http.StatusInternalServerError)
					break
				}
			}
		}))
		client, err := NewAPIClient(s.URL)
		require.NoError(t, err)
		keys := client.ListPrivateKeys()
		require.Equal(t, []string(nil), keys)
	})

	t.Run("error - it returns an empty list of keys if the server returns an invalid response", func(t *testing.T) {
		s := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			switch request.Method {
			case http.MethodGet:
				switch request.URL.Path {
				case "/health":
					writer.WriteHeader(http.StatusOK)
					break
				case "/secrets":
					writer.Header().Set("Content-Type", "application/json")
					writer.WriteHeader(http.StatusOK)
					_, _ = writer.Write([]byte(`invalid`))
					break
				}
			}
		}))
		client, err := NewAPIClient(s.URL)
		require.NoError(t, err)
		keys := client.ListPrivateKeys()
		require.Equal(t, []string(nil), keys)
	})
}

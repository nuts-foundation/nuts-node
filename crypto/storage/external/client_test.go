package external

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/crypto/storage/spi"
	"github.com/nuts-foundation/nuts-node/crypto/util"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

var errResponse = ErrorResponse{
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
				response := SecretResponse{Secret: pem}
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
				response := SecretResponse{Secret: "not-pem"}
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
				storeRequest := StoreSecretRequest{}
				_ = json.Unmarshal(body, &storeRequest)
				assert.Equal(t, StoreSecretRequest{Secret: pem}, storeRequest)
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

func TestAPIClient_CheckHealth(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			switch request.Method {
			case http.MethodGet:
				switch request.URL.Path {
				case "/health":
					writer.WriteHeader(http.StatusOK)
				}
			}
		}))
		defer server.Close()

		client, err := NewAPIClient(server.URL)
		require.NoError(t, err)
		result := client.CheckHealth()
		assert.Equal(t, result[StorageAPIConfigKey].Status, core.HealthStatusUp)
		assert.Empty(t, result[StorageAPIConfigKey].Details)
	})

	t.Run("UNKNOWN when response code is unexpected", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			switch request.Method {
			case http.MethodGet:
				switch request.URL.Path {
				case "/health":
					writer.WriteHeader(http.StatusInternalServerError)
				}
			}
		}))
		defer server.Close()

		client, err := NewAPIClient(server.URL)
		require.NoError(t, err)
		result := client.CheckHealth()
		assert.Equal(t, result[StorageAPIConfigKey].Status, core.HealthStatusUnknown)
		assert.Equal(t, result[StorageAPIConfigKey].Details, "unexpected status code from storage server: 500")
	})

	t.Run("DOWN when response code is unavailable", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			switch request.Method {
			case http.MethodGet:
				switch request.URL.Path {
				case "/health":
					writer.WriteHeader(http.StatusServiceUnavailable)
				}
			}
		}))
		defer server.Close()

		client, err := NewAPIClient(server.URL)
		require.NoError(t, err)
		result := client.CheckHealth()
		assert.Equal(t, result[StorageAPIConfigKey].Status, core.HealthStatusDown)
		assert.Equal(t, result[StorageAPIConfigKey].Details, "storage server reports to be unavailable: 503")
	})

	t.Run("DOWN when server does not responds", func(t *testing.T) {
		client, err := NewAPIClient("http://localhost:1234")
		require.NoError(t, err)
		result := client.CheckHealth()
		assert.Equal(t, result[StorageAPIConfigKey].Status, core.HealthStatusDown)
		assert.Contains(t, result[StorageAPIConfigKey].Details, "connection refused")
	})
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
		assert.EqualError(t, err, "parse \"invalid-url\": invalid URI for request")
		assert.Nil(t, client)
	})

	t.Run("ok - valid url, server not reachable", func(t *testing.T) {
		client, err := NewAPIClient("http://localhost:12345")
		assert.NoError(t, err)
		assert.NotNil(t, client)
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
		require.EqualError(t, err, "unable to get private key: invalid character 'i' looking for beginning of value")
		assert.Nil(t, result)
	})

	t.Run("error - value is not in pem format", func(t *testing.T) {
		client, _ := NewAPIClient(s.URL)
		result, err := client.GetPrivateKey("not-pem")
		require.EqualError(t, err, "unable to parse private key as PEM: failed to decode PEM block containing private key")
		assert.Nil(t, result)
	})

	t.Run("error - content type is not json", func(t *testing.T) {
		client, _ := NewAPIClient(s.URL)
		result, err := client.GetPrivateKey("not-json")
		require.EqualError(t, err, "unable to get private key: no body or wrong content-type")
		assert.Nil(t, result)
	})

	t.Run("error - error response in wrong format", func(t *testing.T) {
		client, _ := NewAPIClient(s.URL)
		result, err := client.GetPrivateKey("bad-request-with-wrong-format")
		require.EqualError(t, err, "unable to get private key: json: cannot unmarshal string into Go value of type external.ErrorResponse")
		assert.Nil(t, result)
	})

	t.Run("error - key not found", func(t *testing.T) {
		client, _ := NewAPIClient(s.URL)

		resolvedKey, err := client.GetPrivateKey("unknown-key")
		require.EqualError(t, err, spi.ErrNotFound.Error())
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
		require.EqualError(t, err, "unable to get private key: unexpected status code from storage server: 500")
		require.Nil(t, resolvedKey)
	})

	t.Run("error - timeout", func(t *testing.T) {
		s := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			time.Sleep(2 * time.Second)
			writer.WriteHeader(http.StatusOK)
		}))
		client, err := NewAPIClient(s.URL)
		require.NoError(t, err)
		key, err := client.GetPrivateKey("test")
		assert.ErrorContains(t, err, "context deadline exceeded")
		assert.Nil(t, key)
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
		require.EqualError(t, err, spi.ErrKeyAlreadyExists.Error())
	})

	t.Run("error - bad request", func(t *testing.T) {
		client, _ := NewAPIClient(s.URL)

		err := client.SavePrivateKey("bad-request", key)
		require.EqualError(t, err, backendError{errResponse}.Error())
	})

	t.Run("error - value is not in PEM format", func(t *testing.T) {
		client, _ := NewAPIClient(s.URL)

		err := client.SavePrivateKey("not-pem", []byte("not-pem"))
		require.EqualError(t, err, "unable to convert private key to PEM format: x509: unknown key type while marshaling PKCS#8: []uint8")
	})

	t.Run("error - error response in wrong format", func(t *testing.T) {
		client, _ := NewAPIClient(s.URL)

		err := client.SavePrivateKey("bad-request-with-wrong-format", key)
		require.EqualError(t, err, "unable to save private key: json: cannot unmarshal string into Go value of type external.ErrorResponse")

	})
	t.Run("error - server error", func(t *testing.T) {
		client, _ := NewAPIClient(s.URL)

		err := client.SavePrivateKey("server-error", key)
		require.EqualError(t, err, "unable to save private key: unexpected status code from storage server: 500")
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
				case "/secrets":
					writer.Header().Set("Content-Type", "application/json")
					writer.WriteHeader(http.StatusOK)
					_, _ = writer.Write([]byte(`[]`))
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
	t.Run("error - it returns nil if the server does not respond with json", func(t *testing.T) {
		s := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			switch request.Method {
			case http.MethodGet:
				switch request.URL.Path {
				case "/secrets":
					writer.Header().Set("Content-Type", "text/plain")
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

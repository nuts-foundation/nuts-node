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

package external

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/crypto/storage/spi"
	"github.com/nuts-foundation/nuts-node/crypto/util"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
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
			case "/secrets/key%2Fwith%2Fslashes":
				fallthrough
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
			switch request.URL.Path {
			case "/secrets/test":
				fallthrough
			case "/secrets/key%2Fwith%2Fslashes":
				body, _ := io.ReadAll(request.Body)
				storeRequest := StoreSecretRequest{}
				_ = json.Unmarshal(body, &storeRequest)
				assert.Equal(t, StoreSecretRequest{Secret: pem}, storeRequest)
				writer.WriteHeader(http.StatusOK)
			case "/secrets/bad-request":
				writer.Header().Set("Content-Type", "application/json")
				responseAsJSON, _ := json.Marshal(errResponse)
				writer.WriteHeader(http.StatusBadRequest)
				_, _ = writer.Write(responseAsJSON)
			case "/secrets/bad-request-with-wrong-format":
				writer.Header().Set("Content-Type", "application/json")
				responseAsJSON, _ := json.Marshal("not-a-valid-error-response")
				writer.WriteHeader(http.StatusBadRequest)
				_, _ = writer.Write(responseAsJSON)
			case "/secrets/existing-key":
				writer.WriteHeader(http.StatusConflict)
			case "/secrets/server-error":
				writer.Header().Set("Content-Type", "application/json")
				writer.WriteHeader(http.StatusInternalServerError)
			default:
				writer.WriteHeader(http.StatusInternalServerError)
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

		client, err := NewAPIClient(server.URL, time.Second)
		require.NoError(t, err)
		result := client.CheckHealth()
		assert.Equal(t, result[StorageType].Status, core.HealthStatusUp)
		assert.Empty(t, result[StorageType].Details)
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

		client, err := NewAPIClient(server.URL, time.Second)
		require.NoError(t, err)
		result := client.CheckHealth()
		assert.Equal(t, result[StorageType].Status, core.HealthStatusUnknown)
		assert.Equal(t, result[StorageType].Details, "unexpected status code from storage server: 500")
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

		client, err := NewAPIClient(server.URL, time.Second)
		require.NoError(t, err)
		result := client.CheckHealth()
		assert.Equal(t, result[StorageType].Status, core.HealthStatusDown)
		assert.Equal(t, result[StorageType].Details, "storage server reports to be unavailable: 503")
	})

	t.Run("DOWN when server does not responds", func(t *testing.T) {
		client, err := NewAPIClient("http://localhost:1234", time.Second)
		require.NoError(t, err)
		result := client.CheckHealth()
		assert.Equal(t, result[StorageType].Status, core.HealthStatusDown)
		assert.Contains(t, result[StorageType].Details, "connection refused")
	})
}

func TestNewAPIClient(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		var key, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		client, err := NewAPIClient(serverWithKey(t, key).URL, time.Second)
		require.NoError(t, err)
		assert.NotNil(t, client)
	})

	t.Run("invalid url", func(t *testing.T) {
		client, err := NewAPIClient("invalid-url", time.Second)
		assert.EqualError(t, err, "parse \"invalid-url\": invalid URI for request")
		assert.Nil(t, client)
	})

	t.Run("ok - valid url, server not reachable", func(t *testing.T) {
		client, err := NewAPIClient("http://localhost:12345", time.Second)
		assert.NoError(t, err)
		assert.NotNil(t, client)
	})
}

func TestAPIClient_GetPrivateKey(t *testing.T) {
	var key, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	s := serverWithKey(t, key)
	t.Run("ok - it should return a private key", func(t *testing.T) {

		client, err := NewAPIClient(s.URL, time.Second)
		require.NoError(t, err)

		resolvedKey, err := client.GetPrivateKey("test")
		require.NoError(t, err)
		assert.Equal(t, key, resolvedKey)
	})

	t.Run("ok - key with a slash in it (should be encoded)", func(t *testing.T) {
		client, _ := NewAPIClient(s.URL, time.Second)

		resolvedKey, err := client.GetPrivateKey("key/with/slashes")
		require.NoError(t, err)
		assert.Equal(t, key, resolvedKey)
	})

	t.Run("error - invalid response body", func(t *testing.T) {
		client, err := NewAPIClient(s.URL, time.Second)
		require.NoError(t, err)

		result, err := client.GetPrivateKey("invalid-response")
		require.EqualError(t, err, "unable to read private key: invalid character 'i' looking for beginning of value")
		assert.Nil(t, result)
	})

	t.Run("error - value is not in pem format", func(t *testing.T) {
		client, _ := NewAPIClient(s.URL, time.Second)
		result, err := client.GetPrivateKey("not-pem")
		require.EqualError(t, err, "unable to parse private key as PEM: failed to decode PEM block containing private key")
		assert.Nil(t, result)
	})

	t.Run("error - content type is not json", func(t *testing.T) {
		client, _ := NewAPIClient(s.URL, time.Second)
		result, err := client.GetPrivateKey("not-json")
		require.EqualError(t, err, "invalid private key response from server")
		assert.Nil(t, result)
	})

	t.Run("error - error response in wrong format", func(t *testing.T) {
		client, _ := NewAPIClient(s.URL, time.Second)
		result, err := client.GetPrivateKey("bad-request-with-wrong-format")
		require.EqualError(t, err, "unable to read private key: server returned HTTP 400 (expected: 200)")
		assert.Nil(t, result)
	})

	t.Run("error - key not found", func(t *testing.T) {
		client, _ := NewAPIClient(s.URL, time.Second)

		resolvedKey, err := client.GetPrivateKey("unknown-key")
		require.EqualError(t, err, spi.ErrNotFound.Error())
		require.Nil(t, resolvedKey)
	})

	t.Run("error - bad request", func(t *testing.T) {
		client, _ := NewAPIClient(s.URL, time.Second)

		resolvedKey, err := client.GetPrivateKey("bad-request")
		require.EqualError(t, err, "unable to read private key: server returned HTTP 400 (expected: 200)")
		require.Nil(t, resolvedKey)
	})
	t.Run("error - server error", func(t *testing.T) {
		client, _ := NewAPIClient(s.URL, time.Second)

		resolvedKey, err := client.GetPrivateKey("server-error")
		require.EqualError(t, err, "unable to read private key: server returned HTTP 500 (expected: 200)")
		require.Nil(t, resolvedKey)
	})

	t.Run("error - timeout", func(t *testing.T) {
		s := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			time.Sleep(2 * time.Second)
			writer.WriteHeader(http.StatusOK)
		}))
		client, err := NewAPIClient(s.URL, time.Second)
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
		client, _ := NewAPIClient(s.URL, time.Second)

		err := client.SavePrivateKey("test", key)
		require.NoError(t, err)
	})

	t.Run("ok - key with a slash in it (should be encoded)", func(t *testing.T) {
		client, _ := NewAPIClient(s.URL, time.Second)

		err := client.SavePrivateKey("key/with/slashes", key)
		require.NoError(t, err)
	})

	t.Run("error - key already exists", func(t *testing.T) {
		client, _ := NewAPIClient(s.URL, time.Second)

		err := client.SavePrivateKey("existing-key", key)
		require.EqualError(t, err, spi.ErrKeyAlreadyExists.Error())
	})

	t.Run("error - bad request", func(t *testing.T) {
		client, _ := NewAPIClient(s.URL, time.Second)

		err := client.SavePrivateKey("bad-request", key)
		require.EqualError(t, err, "unable to save private key: server returned HTTP 400 (expected: 200)")
	})

	t.Run("error - value is not in PEM format", func(t *testing.T) {
		client, _ := NewAPIClient(s.URL, time.Second)

		err := client.SavePrivateKey("not-pem", []byte("not-pem"))
		require.EqualError(t, err, "unable to convert private key to PEM format: x509: unknown key type while marshaling PKCS#8: []uint8")
	})

	t.Run("error - error response in wrong format", func(t *testing.T) {
		client, _ := NewAPIClient(s.URL, time.Second)

		err := client.SavePrivateKey("bad-request-with-wrong-format", key)
		require.EqualError(t, err, "unable to save private key: server returned HTTP 400 (expected: 200)")

	})
	t.Run("error - server error", func(t *testing.T) {
		client, _ := NewAPIClient(s.URL, time.Second)

		err := client.SavePrivateKey("server-error", key)
		require.EqualError(t, err, "unable to save private key: server returned HTTP 500 (expected: 200)")
	})
}

func TestAPIClient_PrivateKeyExists(t *testing.T) {
	var key, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	s := serverWithKey(t, key)

	t.Run("ok - it should return true if the key exists", func(t *testing.T) {
		client, _ := NewAPIClient(s.URL, time.Second)

		exists := client.PrivateKeyExists("test")
		require.True(t, exists)
	})

	t.Run("ok - key with a slash in it (should be encoded)", func(t *testing.T) {
		client, _ := NewAPIClient(s.URL, time.Second)

		exists := client.PrivateKeyExists("key/with/slashes")
		require.True(t, exists)
	})

	t.Run("ok - it should return false if the key does not exist", func(t *testing.T) {
		client, _ := NewAPIClient(s.URL, time.Second)

		exists := client.PrivateKeyExists("unknown-key")
		require.False(t, exists)
	})

	t.Run("error - it returns false if the server returns an error", func(t *testing.T) {
		client, _ := NewAPIClient(s.URL, time.Second)

		exists := client.PrivateKeyExists("bad-request")
		require.False(t, exists)
	})

	t.Run("error - it returns false if the response has an invalid format", func(t *testing.T) {
		client, _ := NewAPIClient(s.URL, time.Second)

		exists := client.PrivateKeyExists("invalid-response")
		require.False(t, exists)
	})
}

func TestAPIClient_ListPrivateKeys(t *testing.T) {
	t.Run("ok - it returns an empty list of keys when no keys are returned by the server", func(t *testing.T) {
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
		client, err := NewAPIClient(s.URL, time.Second)
		require.NoError(t, err)
		keys := client.ListPrivateKeys()
		require.Equal(t, []string{}, keys)
	})

	t.Run("ok - it returns a list of unescaped keys", func(t *testing.T) {
		complexKeyName := "private-key/did:example:123#key2"
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
					_, _ = writer.Write([]byte(fmt.Sprintf(`["%s", "%s"]`, "key1", url.PathEscape(complexKeyName))))
					break
				}
			}
		}))
		client, err := NewAPIClient(s.URL, time.Second)
		require.NoError(t, err)
		keys := client.ListPrivateKeys()
		require.Equal(t, []string{"key1", complexKeyName}, keys)
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
		client, err := NewAPIClient(s.URL, time.Second)
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
		client, err := NewAPIClient(s.URL, time.Second)
		require.NoError(t, err)
		keys := client.ListPrivateKeys()
		require.Equal(t, []string(nil), keys)
	})
	t.Run("error - it returns an empty list of keys if the server does not respond with json", func(t *testing.T) {
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
		client, err := NewAPIClient(s.URL, time.Second)
		require.NoError(t, err)
		keys := client.ListPrivateKeys()
		require.Equal(t, []string(nil), keys)
	})
}

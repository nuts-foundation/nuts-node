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
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"github.com/nuts-foundation/nuts-node/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/crypto/storage/spi"
	"github.com/nuts-foundation/nuts-node/crypto/util"
)

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
			case "/secrets/servererror-with-invalid-response":
				// tests the case where the server returns an error but the response is not a valid json error response
				writer.Header().Set("Content-Type", "application/json")
				responseAsJSON, _ := json.Marshal("not-a-valid-error-response")
				writer.WriteHeader(http.StatusInternalServerError)
				_, _ = writer.Write(responseAsJSON)
				break
			case "/secrets/server-error":
				writer.Header().Set("Content-Type", "application/json")
				responseAsJSON, _ := json.Marshal(ErrorResponse{Title: "server error"})
				writer.WriteHeader(http.StatusInternalServerError)
				_, _ = writer.Write(responseAsJSON)
				break
			case "/secrets/server-error-plain-text":
				writer.Header().Set("Content-Type", "text/plain")
				writer.WriteHeader(http.StatusInternalServerError)
				_, _ = writer.Write([]byte("server error"))
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
			case "/secrets/servererror-with-invalid-response":
				writer.Header().Set("Content-Type", "application/json")
				responseAsJSON, _ := json.Marshal("not-a-valid-error-response")
				writer.WriteHeader(http.StatusInternalServerError)
				_, _ = writer.Write(responseAsJSON)
			case "/secrets/existing-key":
				writer.WriteHeader(http.StatusConflict)
			case "/secrets/server-error":
				writer.Header().Set("Content-Type", "application/json")
				errResponse := ErrorResponse{Title: "Server Error", Detail: "Internal Server Error", Status: 500}
				errAsJson, _ := json.Marshal(errResponse)
				writer.WriteHeader(http.StatusInternalServerError)
				writer.Write(errAsJson)
			case "/secrets/bad-request":
				writer.Header().Set("Content-Type", "application/json")
				errResponse := ErrorResponse{Title: "Missing secret", Detail: "Secret field is missing from post body", Status: 400}
				errAsJson, _ := json.Marshal(errResponse)
				writer.WriteHeader(http.StatusBadRequest)
				writer.Write(errAsJson)
			case "/secrets/server-error-plain-text":
				writer.Header().Set("Content-Type", "text/plain")
				writer.WriteHeader(http.StatusInternalServerError)
				_, _ = writer.Write([]byte("server error"))
				break
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

		client, err := NewAPIClient(Config{Address: server.URL, Timeout: time.Second})
		NewAPIClient(Config{Address: server.URL, Timeout: time.Second})
		require.NoError(t, err)
		result := client.CheckHealth()
		assert.Equal(t, result[StorageType].Status, core.HealthStatusUp)
		assert.Empty(t, result[StorageType].Details)
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

		client, err := NewAPIClient(Config{Address: server.URL, Timeout: time.Second})
		require.NoError(t, err)
		result := client.CheckHealth()
		assert.Equal(t, core.HealthStatusDown, result[StorageType].Status)
		assert.Equal(t, "unexpected status code from storage server: 503", result[StorageType].Details)
	})

	t.Run("DOWN when server does not responds", func(t *testing.T) {
		client, err := NewAPIClient(Config{"http://localhost:1234", time.Second})
		require.NoError(t, err)
		result := client.CheckHealth()
		assert.Equal(t, core.HealthStatusDown, result[StorageType].Status)
		assert.Contains(t, result[StorageType].Details, "connection refused")
	})
}

func TestNewAPIClient(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		var key, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		client, err := NewAPIClient(Config{Address: serverWithKey(t, key).URL, Timeout: time.Second})
		require.NoError(t, err)
		assert.NotNil(t, client)
	})

	t.Run("invalid url", func(t *testing.T) {
		client, err := NewAPIClient(Config{"invalid-url", time.Second})
		assert.EqualError(t, err, "parse \"invalid-url\": invalid URI for request")
		assert.Nil(t, client)
	})

	t.Run("ok - valid url, server not reachable", func(t *testing.T) {
		client, err := NewAPIClient(Config{"http://localhost:12345", time.Second})
		assert.NoError(t, err)
		assert.NotNil(t, client)
	})
}

func TestAPIClient_GetPrivateKey(t *testing.T) {
	var key, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ctx := context.Background()

	s := serverWithKey(t, key)
	t.Run("ok - it should return a private key", func(t *testing.T) {

		client, err := NewAPIClient(Config{s.URL, time.Second})
		require.NoError(t, err)

		resolvedKey, err := client.GetPrivateKey(ctx, "test", "")
		require.NoError(t, err)
		assert.Equal(t, key, resolvedKey)
	})

	t.Run("ok - key with a slash in it (should be encoded)", func(t *testing.T) {
		client, _ := NewAPIClient(Config{s.URL, time.Second})

		resolvedKey, err := client.GetPrivateKey(ctx, "key/with/slashes", "")
		require.NoError(t, err)
		assert.Equal(t, key, resolvedKey)
	})

	t.Run("error - invalid response body", func(t *testing.T) {
		client, err := NewAPIClient(Config{s.URL, time.Second})
		require.NoError(t, err)

		result, err := client.GetPrivateKey(ctx, "invalid-response", "")
		require.EqualError(t, err, "unable to get private key: invalid character 'i' looking for beginning of value")
		assert.Nil(t, result)
	})

	t.Run("error - value is not in pem format", func(t *testing.T) {
		client, _ := NewAPIClient(Config{s.URL, time.Second})
		result, err := client.GetPrivateKey(ctx, "not-pem", "")
		require.EqualError(t, err, "unable to parse private key as PEM: failed to decode PEM block containing private key")
		assert.Nil(t, result)
	})

	t.Run("error - content type is not json", func(t *testing.T) {
		client, _ := NewAPIClient(Config{s.URL, time.Second})
		result, err := client.GetPrivateKey(ctx, "not-json", "")
		require.EqualError(t, err, "invalid private key response from server")
		assert.Nil(t, result)
	})

	t.Run("error - error response in wrong format", func(t *testing.T) {
		client, _ := NewAPIClient(Config{s.URL, time.Second})
		result, err := client.GetPrivateKey(ctx, "servererror-with-invalid-response", "")
		require.EqualError(t, err, "unable to get private key: json: cannot unmarshal string into Go value of type external.ErrorResponse")
		assert.Nil(t, result)
	})

	t.Run("error - key not found", func(t *testing.T) {
		client, _ := NewAPIClient(Config{s.URL, time.Second})

		resolvedKey, err := client.GetPrivateKey(ctx, "unknown-key", "")
		require.EqualError(t, err, spi.ErrNotFound.Error())
		require.Nil(t, resolvedKey)
	})

	t.Run("error - server error", func(t *testing.T) {
		client, _ := NewAPIClient(Config{s.URL, time.Second})

		resolvedKey, err := client.GetPrivateKey(ctx, "server-error", "")
		require.EqualError(t, err, "unable to get private key: server error")
		require.Nil(t, resolvedKey)
	})

	t.Run("error - plain text response", func(t *testing.T) {
		client, _ := NewAPIClient(Config{s.URL, time.Second})

		resolvedKey, err := client.GetPrivateKey(ctx, "server-error-plain-text", "")
		require.EqualError(t, err, "unable to get private key: server returned HTTP 500")
		require.Nil(t, resolvedKey)
	})

	t.Run("error - timeout", func(t *testing.T) {
		s := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			time.Sleep(2 * time.Second)
			writer.WriteHeader(http.StatusOK)
		}))
		client, err := NewAPIClient(Config{s.URL, time.Second})
		require.NoError(t, err)
		key, err := client.GetPrivateKey(ctx, "test", "")
		assert.ErrorContains(t, err, "context deadline exceeded")
		assert.Nil(t, key)
	})

}

func TestAPIClient_SavePrivateKey(t *testing.T) {
	var key, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	s := serverWithKey(t, key)
	ctx := context.Background()

	t.Run("ok - it should store a private key", func(t *testing.T) {
		client, _ := NewAPIClient(Config{s.URL, time.Second})

		err := client.SavePrivateKey(ctx, "test", key)
		require.NoError(t, err)
	})

	t.Run("ok - key with a slash in it (should be encoded)", func(t *testing.T) {
		client, _ := NewAPIClient(Config{s.URL, time.Second})

		err := client.SavePrivateKey(ctx, "key/with/slashes", key)
		require.NoError(t, err)
	})

	t.Run("error - key already exists", func(t *testing.T) {
		client, _ := NewAPIClient(Config{s.URL, time.Second})

		err := client.SavePrivateKey(ctx, "existing-key", key)
		require.EqualError(t, err, spi.ErrKeyAlreadyExists.Error())
	})

	t.Run("error - value is not in PEM format", func(t *testing.T) {
		client, _ := NewAPIClient(Config{s.URL, time.Second})

		err := client.SavePrivateKey(ctx, "not-pem", []byte("not-pem"))
		require.EqualError(t, err, "unable to convert private key to PEM format: x509: unknown key type while marshaling PKCS#8: []uint8")
	})

	t.Run("error - server error, response in wrong format", func(t *testing.T) {
		client, _ := NewAPIClient(Config{s.URL, time.Second})

		err := client.SavePrivateKey(ctx, "servererror-with-invalid-response", key)
		require.EqualError(t, err, "unable to save private key: json: cannot unmarshal string into Go value of type external.ErrorResponse")

	})
	t.Run("error - server error", func(t *testing.T) {
		client, _ := NewAPIClient(Config{s.URL, time.Second})

		err := client.SavePrivateKey(ctx, "server-error", key)
		require.EqualError(t, err, "unable to save private key: Server Error")
	})

	t.Run("error - server error in plain text", func(t *testing.T) {
		client, _ := NewAPIClient(Config{s.URL, time.Second})

		err := client.SavePrivateKey(ctx, "server-error-plain-text", key)
		require.EqualError(t, err, "unable to save private key: server returned HTTP 500")
	})

	t.Run("error - bad request", func(t *testing.T) {
		client, _ := NewAPIClient(Config{s.URL, time.Second})

		err := client.SavePrivateKey(ctx, "bad-request", key)
		require.EqualError(t, err, "unable to save private key: bad request: Missing secret")
	})

	t.Run("error - timeout", func(t *testing.T) {
		s := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			time.Sleep(2 * time.Second)
			writer.WriteHeader(http.StatusOK)
		}))
		client, err := NewAPIClient(Config{s.URL, time.Second})
		require.NoError(t, err)
		err = client.SavePrivateKey(ctx, "test", key)
		assert.ErrorContains(t, err, "context deadline exceeded")
	})
}

func TestAPIClient_PrivateKeyExists(t *testing.T) {
	var key, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	s := serverWithKey(t, key)
	ctx := context.Background()

	t.Run("ok - it should return true if the key exists", func(t *testing.T) {
		client, _ := NewAPIClient(Config{s.URL, time.Second})

		exists, err := client.PrivateKeyExists(ctx, "test", "")
		require.NoError(t, err)
		require.True(t, exists)
	})

	t.Run("ok - key with a slash in it (should be encoded)", func(t *testing.T) {
		client, _ := NewAPIClient(Config{s.URL, time.Second})

		exists, err := client.PrivateKeyExists(ctx, "key/with/slashes", "")
		require.NoError(t, err)
		require.True(t, exists)
	})

	t.Run("ok - it should return false if the key does not exist", func(t *testing.T) {
		client, _ := NewAPIClient(Config{s.URL, time.Second})

		exists, err := client.PrivateKeyExists(ctx, "unknown-key", "")
		require.NoError(t, err)
		require.False(t, exists)
	})

	t.Run("error - it returns false if the server returns an error", func(t *testing.T) {
		client, _ := NewAPIClient(Config{s.URL, time.Second})

		exists, err := client.PrivateKeyExists(ctx, "server-error", "")
		require.Error(t, err)
		require.False(t, exists)
	})

	t.Run("error - it returns false if the response has an invalid format", func(t *testing.T) {
		client, _ := NewAPIClient(Config{s.URL, time.Second})

		exists, err := client.PrivateKeyExists(ctx, "invalid-response", "")
		require.Error(t, err)
		require.False(t, exists)
	})
}

func TestAPIClient_ListPrivateKeys(t *testing.T) {
	ctx := context.Background()

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
		client, err := NewAPIClient(Config{s.URL, time.Second})
		require.NoError(t, err)
		keys := client.ListPrivateKeys(ctx)
		require.Equal(t, []spi.KeyNameVersion{}, keys)
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
					_, _ = writer.Write([]byte(fmt.Sprintf(`["%s", "%s"]`, "key1", complexKeyName)))
					break
				}
			}
		}))
		client, err := NewAPIClient(Config{s.URL, time.Second})
		require.NoError(t, err)
		keys := client.ListPrivateKeys(ctx)
		require.Equal(t, []spi.KeyNameVersion{{"key1", "1"}, {complexKeyName, "1"}}, keys)
	})

	t.Run("error - it returns an empty list of keys if the server returns an error", func(t *testing.T) {
		s := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			switch request.Method {
			case http.MethodGet:
				switch request.URL.Path {
				case "/secrets":
					writer.Header().Set("Content-Type", "application/json")
					writer.WriteHeader(http.StatusInternalServerError)
					writer.Write([]byte(`{"error": "internal server error"}`))
					break
				}
			}
		}))
		client, err := NewAPIClient(Config{s.URL, time.Second})
		require.NoError(t, err)
		keys := client.ListPrivateKeys(ctx)
		require.Equal(t, []spi.KeyNameVersion(nil), keys)
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
		client, err := NewAPIClient(Config{s.URL, time.Second})
		require.NoError(t, err)
		keys := client.ListPrivateKeys(ctx)
		require.Equal(t, []spi.KeyNameVersion(nil), keys)
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
		client, err := NewAPIClient(Config{s.URL, time.Second})
		require.NoError(t, err)
		keys := client.ListPrivateKeys(ctx)
		require.Equal(t, []spi.KeyNameVersion(nil), keys)
	})
}

func TestAPIClient_DeletePrivateKey(t *testing.T) {
	ctx := context.Background()

	t.Run("ok - it should delete a private key", func(t *testing.T) {
		s := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			switch request.Method {
			case http.MethodDelete:
				switch request.URL.Path {
				case "/secrets/test":
					writer.WriteHeader(http.StatusOK)
					break
				}
			}
		}))
		client, err := NewAPIClient(Config{s.URL, time.Second})
		require.NoError(t, err)

		err = client.DeletePrivateKey(ctx, "test")
		require.NoError(t, err)
	})

	t.Run("ok - key with a slash in it (should be encoded)", func(t *testing.T) {
		s := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			switch request.Method {
			case http.MethodDelete:
				switch request.URL.Path {
				case "/secrets/key%2Fwith%2Fslashes":
					writer.WriteHeader(http.StatusOK)
					break
				}
			}
		}))
		client, err := NewAPIClient(Config{s.URL, time.Second})
		require.NoError(t, err)

		err = client.DeletePrivateKey(ctx, "key/with/slashes")
		require.NoError(t, err)
	})

	t.Run("error - key not found", func(t *testing.T) {
		s := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			switch request.Method {
			case http.MethodDelete:
				switch request.URL.Path {
				case "/secrets/unknown-key":
					writer.WriteHeader(http.StatusNotFound)
					break
				}
			}
		}))
		client, err := NewAPIClient(Config{s.URL, time.Second})
		require.NoError(t, err)

		err = client.DeletePrivateKey(ctx, "unknown-key")
		require.EqualError(t, err, spi.ErrNotFound.Error())
	})

	t.Run("error - server error", func(t *testing.T) {
		s := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			switch request.Method {
			case http.MethodDelete:
				switch request.URL.Path {
				case "/secrets/server-error":
					writer.WriteHeader(http.StatusInternalServerError)
					break
				}
			}
		}))
		client, err := NewAPIClient(Config{s.URL, time.Second})
		require.NoError(t, err)

		err = client.DeletePrivateKey(ctx, "server-error")

		require.EqualError(t, err, "unable to delete private key: server returned HTTP 500")
	})
}

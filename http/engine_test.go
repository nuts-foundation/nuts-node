/*
 * Copyright (C) 2022 Nuts community
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

package http

import (
	"bytes"
	"crypto/ed25519"
	b64 "encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/http/log"
	"github.com/nuts-foundation/nuts-node/test"
	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/writer"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

const securedPath = "/internal/landing"
const unsecuredPath = "/other"

func TestEngine_Configure(t *testing.T) {
	noop := func() {}

	t.Run("ok", func(t *testing.T) {
		engine := New(noop, nil)
		engine.config = createTestConfig()

		err := engine.Configure(*core.NewServerConfig())
		require.NoError(t, err)
		err = engine.Start()
		require.NoError(t, err)
		defer engine.Shutdown()

		assertServerStarted(t, engine.config.Internal.Address)
		assertHTTPRequest(t, engine.config.Internal.Address)
		assertServerStarted(t, engine.config.Public.Address)
		assertHTTPRequest(t, engine.config.Public.Address)

		err = engine.Shutdown()
		assert.NoError(t, err)
	})
	t.Run("middleware", func(t *testing.T) {
		t.Run("auth-tokenV2", func(t *testing.T) {
			// Ensure the server can be started and protected without applying a specific audience in the configuration
			t.Run("default audience", func(t *testing.T) {
				// Use the system hostname as the audience (but do not configure it specifically)
				audience, err := os.Hostname()
				require.NoError(t, err)

				// Create a key and associated JWT that will be valid
				_, serializer, authorizedKeys := generateEd25519TestKey(t)
				token := validJWT(t, audience)
				serializedToken, err := serializer.Serialize(token)
				require.NoError(t, err)

				// Create a temporary authorized_keys file which will be deleted upon returning from this function
				authorizedKeysFile, err := os.CreateTemp("", "tmp.authorized_keys-")
				require.NoError(t, err)
				defer os.Remove(authorizedKeysFile.Name())
				authorizedKeysFile.Write(authorizedKeys)
				authorizedKeysFile.Close()

				// Setup a new HTTP engine
				engine := New(noop, nil)
				engine.config = createTestConfig()

				// Configure the default interface without authentication
				engine.config.Internal.Auth = AuthConfig{
					Type:               BearerTokenAuthV2,
					AuthorizedKeysPath: authorizedKeysFile.Name(),
				}

				// Apply the configuration built above
				err = engine.Configure(*core.NewServerConfig())
				require.NoError(t, err)

				// Setup a request handler for capturing the authenticated username from the echo context
				var capturedUser string
				captureUser := func(c echo.Context) error {
					userContext := c.Get(core.UserContextKey)
					if userContext == nil {
						capturedUser = ""
						return nil
					}
					capturedUser = userContext.(string)
					return nil
				}

				// Apply the previously defined request handler at various endpoints on the HTTP engine
				engine.Router().GET(securedPath, captureUser)

				// Start the HTTP engine, ensuring it will be shutdown later
				_ = engine.Start()
				defer engine.Shutdown()

				// Check that the HTTP server has started listening for requests
				assertServerStarted(t, engine.config.Internal.Address)

				// Make a test request
				capturedUser = ""
				request, _ := http.NewRequest(http.MethodGet, "http://"+engine.config.Internal.Address+securedPath, nil)
				log.Logger().Infof("requesting %v", request.URL.String())
				request.Header.Set("Authorization", "Bearer "+string(serializedToken))
				request.Header.Set(engine.config.ClientIPHeaderName, "1.2.3.4")
				response, err := http.DefaultClient.Do(request)

				assert.NoError(t, err)
				assert.Equal(t, http.StatusOK, response.StatusCode)
				assert.Equal(t, "random@test.local", capturedUser)
			})

			t.Run("specific audience", func(t *testing.T) {
				// Create a key and associated JWT that will be valid
				_, serializer, authorizedKeys := generateEd25519TestKey(t)
				token := validJWT(t, "foo")
				serializedToken, err := serializer.Serialize(token)
				require.NoError(t, err)

				// Create another key and associated JWT that will be invalid
				_, attackerSerializer, _ := generateEd25519TestKey(t)
				attackerToken := validJWT(t, "foo")
				serializedAttackerToken, err := attackerSerializer.Serialize(attackerToken)
				require.NoError(t, err)

				// Create a temporary authorized_keys file which will be deleted upon returning from this function
				authorizedKeysFile, err := os.CreateTemp("", "tmp.authorized_keys-")
				require.NoError(t, err)
				defer os.Remove(authorizedKeysFile.Name())
				authorizedKeysFile.Write(authorizedKeys)
				authorizedKeysFile.Close()

				// Setup a new HTTP engine
				engine := New(noop, nil)
				engine.config = createTestConfig()
				engine.config.Internal.Auth = AuthConfig{
					Type:               BearerTokenAuthV2,
					Audience:           "foo",
					AuthorizedKeysPath: authorizedKeysFile.Name(),
				}

				// Apply the configuration built above
				err = engine.Configure(*core.NewServerConfig())
				require.NoError(t, err)

				// Setup a request handler for capturing the authenticated username from the echo context
				var capturedUser string
				captureUser := func(c echo.Context) error {
					userContext := c.Get(core.UserContextKey)
					if userContext == nil {
						capturedUser = ""
						return nil
					}
					capturedUser = userContext.(string)
					return nil
				}

				// Apply the previously defined request handler at various endpoints on the HTTP engine
				engine.Router().GET(securedPath, captureUser)
				engine.Router().GET(unsecuredPath, captureUser)

				// Start the HTTP engine, ensuring it will be shutdown later
				_ = engine.Start()
				defer engine.Shutdown()

				// Check that the HTTP server has started listening for requests
				assertServerStarted(t, engine.config.Internal.Address)

				t.Run("success", func(t *testing.T) {
					capturedUser = ""
					request, _ := http.NewRequest(http.MethodGet, "http://"+engine.config.Internal.Address+securedPath, nil)
					log.Logger().Infof("requesting %v", request.URL.String())
					request.Header.Set("Authorization", "Bearer "+string(serializedToken))
					response, err := http.DefaultClient.Do(request)

					assert.NoError(t, err)
					assert.Equal(t, http.StatusOK, response.StatusCode)
					assert.Equal(t, "random@test.local", capturedUser)
				})
				t.Run("no token", func(t *testing.T) {
					capturedUser = ""
					request, _ := http.NewRequest(http.MethodGet, "http://"+engine.config.Internal.Address+securedPath, nil)
					log.Logger().Infof("requesting %v", request.URL.String())
					response, err := http.DefaultClient.Do(request)

					assert.NoError(t, err)
					assert.Equal(t, http.StatusUnauthorized, response.StatusCode)
					assert.Empty(t, capturedUser)
				})
				t.Run("invalid token", func(t *testing.T) {
					capturedUser = ""
					request, _ := http.NewRequest(http.MethodGet, "http://"+engine.config.Internal.Address+securedPath, nil)
					log.Logger().Infof("requesting %v", request.URL.String())
					response, err := http.DefaultClient.Do(request)
					request.Header.Set("Authorization", "Bearer invalid")

					assert.NoError(t, err)
					assert.Equal(t, http.StatusUnauthorized, response.StatusCode)
					assert.Empty(t, capturedUser)
				})
				t.Run("invalid token (incorrect signing key)", func(t *testing.T) {
					capturedUser = ""
					request, _ := http.NewRequest(http.MethodGet, "http://"+engine.config.Internal.Address+securedPath, nil)
					log.Logger().Infof("requesting %v", request.URL.String())
					response, err := http.DefaultClient.Do(request)
					request.Header.Set("Authorization", "Bearer "+string(serializedAttackerToken))

					assert.NoError(t, err)
					assert.Equal(t, http.StatusUnauthorized, response.StatusCode)
					assert.Empty(t, capturedUser)
				})
			})
		})
	})
}

func TestEngine_LoggingMiddleware(t *testing.T) {
	output := new(bytes.Buffer)
	logrus.StandardLogger().AddHook(&writer.Hook{
		Writer:    output,
		LogLevels: []logrus.Level{logrus.InfoLevel, logrus.DebugLevel},
	})

	noop := func() {}

	t.Run("requestLogger", func(t *testing.T) {
		engine := New(noop, nil)
		engine.config.Internal.Address = fmt.Sprintf("localhost:%d", test.FreeTCPPort())
		engine.config.ClientIPHeaderName = "X-Custom-Header"

		err := engine.Configure(*core.NewServerConfig())
		require.NoError(t, err)

		engine.Router().GET("/some-path", func(c echo.Context) error {
			return nil
		})

		err = engine.Start()
		require.NoError(t, err)
		defer engine.Shutdown()

		assertServerStarted(t, engine.config.Internal.Address)

		t.Run("applies default filters", func(t *testing.T) {
			// Calls to /status, ... are not logged
			for _, path := range []string{"/status", "/metrics", "/health"} {
				output.Reset()
				_, _ = http.Get("http://" + engine.config.Internal.Address + path)
				assert.Empty(t, output.String(), path+" should not be logged")
			}
		})

		t.Run("logs requests", func(t *testing.T) {
			// Call to another, registered path is logged
			output.Reset()
			_, _ = http.Get("http://" + engine.config.Internal.Address + "/some-path")
			assert.Contains(t, output.String(), "HTTP request")
		})
		t.Run("ip log - custom header", func(t *testing.T) {
			// Call to another, registered path is logged
			output.Reset()
			request, _ := http.NewRequest(http.MethodGet, "http://"+engine.config.Internal.Address+"/some-path", nil)
			request.Header.Set(engine.config.ClientIPHeaderName, "1.2.3.4")
			_, err = http.DefaultClient.Do(request)
			require.NoError(t, err)
			assert.Contains(t, output.String(), "remote_ip=1.2.3.4")
		})
		t.Run("ip log - custom header missing", func(t *testing.T) {
			// Call to another, registered path is logged
			output.Reset()
			request, _ := http.NewRequest(http.MethodGet, "http://"+engine.config.Internal.Address+"/some-path", nil)
			request.Header.Set(engine.config.ClientIPHeaderName, "")
			_, err = http.DefaultClient.Do(request)
			require.NoError(t, err)
			assert.Contains(t, output.String(), "remote_ip=127.0.0.1")
		})
	})
	t.Run("bodyLogger", func(t *testing.T) {
		engine := New(noop, nil)
		engine.config = createTestConfig()
		engine.config.Log = LogMetadataAndBodyLevel

		err := engine.Configure(*core.NewServerConfig())
		require.NoError(t, err)
		engine.Router().POST("/", func(c echo.Context) error {
			return c.JSON(200, "hello, world")
		})

		err = engine.Start()
		require.NoError(t, err)
		defer engine.Shutdown()

		assertServerStarted(t, engine.config.Internal.Address)

		t.Run("logs bodies", func(t *testing.T) {
			output.Reset()
			_, _ = http.Post("http://"+engine.config.Public.Address, "application/json", bytes.NewReader([]byte("{}")))
			assert.Contains(t, output.String(), "HTTP request body: {}")
			assert.Contains(t, output.String(), `HTTP response body: \"hello, world\"`)
		})
	})
}

func assertServerStarted(t *testing.T, address string) {
	t.Helper()
	var err error
	var conn net.Conn
	for i := 0; i < 10; i++ {
		conn, err = net.DialTimeout("tcp", address, 100*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("Server did not start in time", err)
}

func assertHTTPRequest(t *testing.T, address string) {
	t.Helper()
	response, err := http.Get("http://" + address)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.ReadAll(response.Body)
}

// generateEd25519TestKey generates a new private key for use in testing also returning a jwt serializer and the ssh authorized_keys representation
func generateEd25519TestKey(t *testing.T) (jwk.Key, *jwt.Serializer, []byte) {
	// Generate a new ed25519 key
	pub, priv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)

	// Convert the public key to an ssh key, generating an authorized key representation
	sshPub, err := ssh.NewPublicKey(pub)
	require.NoError(t, err)
	sshAuthKey := fmt.Sprintf("%v %v random@test.local", sshPub.Type(), b64.StdEncoding.EncodeToString(sshPub.Marshal()))

	// Convert the base key type to a jwk type
	jwkKey, err := jwk.FromRaw(priv)
	require.NoError(t, err)

	// Set the key ID for the jwk to be the public key fingerprint
	err = jwkKey.Set(jwk.KeyIDKey, ssh.FingerprintSHA256(sshPub))
	require.NoError(t, err)

	// Create a serializer configured to use the generated key
	serializer := jwt.NewSerializer().Sign(jwt.WithKey(jwa.EdDSA, jwkKey))

	t.Logf("authorized_key = %v", sshAuthKey)

	// Return the jwk and authorized_key representation
	return jwkKey, serializer, []byte(sshAuthKey)
}

// validJWT returns a valid JWT
func validJWT(t *testing.T, host string) jwt.Token {
	issuedAt := time.Now()
	notBefore := issuedAt
	expires := notBefore.Add(time.Second * time.Duration(300))
	token, err := jwt.NewBuilder().
		Issuer("random@test.local").
		Subject("random@test.local").
		Audience([]string{host}).
		IssuedAt(issuedAt).
		NotBefore(notBefore).
		Expiration(expires).
		JwtID(uuid.NewString()).
		Build()
	require.NoError(t, err)
	return token
}

func createTestConfig() Config {
	testConfig := DefaultConfig()
	testConfig.Internal.Address = fmt.Sprintf("localhost:%d", test.FreeTCPPort())
	testConfig.Public.Address = fmt.Sprintf("localhost:%d", test.FreeTCPPort())
	return testConfig
}

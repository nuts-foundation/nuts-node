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
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	b64 "encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jwt"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/http/log"
	"github.com/nuts-foundation/nuts-node/test"
	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/writer"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

func TestEngine_Configure(t *testing.T) {
	noop := func() {}

	t.Run("ok, no TLS (default)", func(t *testing.T) {
		engine := New(noop, nil)
		engine.config.InterfaceConfig.Address = fmt.Sprintf(":%d", test.FreeTCPPort())
		engine.config.InterfaceConfig.TLSMode = ""

		err := engine.Configure(*core.NewServerConfig())
		require.NoError(t, err)
		err = engine.Start()
		require.NoError(t, err)
		defer engine.Shutdown()

		assertServerStarted(t, engine.config.InterfaceConfig.Address)
		assertHTTPRequest(t, engine.config.InterfaceConfig.Address)

		err = engine.Shutdown()
		assert.NoError(t, err)
	})
	t.Run("ok, no TLS (explicitly disabled)", func(t *testing.T) {
		engine := New(noop, nil)
		engine.config.InterfaceConfig.Address = fmt.Sprintf(":%d", test.FreeTCPPort())
		engine.config.InterfaceConfig.TLSMode = TLSDisabledMode

		err := engine.Configure(*core.NewServerConfig())
		require.NoError(t, err)
		err = engine.Start()
		require.NoError(t, err)
		defer engine.Shutdown()

		assertServerStarted(t, engine.config.InterfaceConfig.Address)
		assertHTTPRequest(t, engine.config.InterfaceConfig.Address)

		err = engine.Shutdown()
		assert.NoError(t, err)
	})
	t.Run("TLS", func(t *testing.T) {
		serverCfg := core.NewServerConfig()
		serverCfg.TLS.CertFile = "../test/pki/certificate-and-key.pem"
		serverCfg.TLS.CertKeyFile = "../test/pki/certificate-and-key.pem"
		serverCfg.TLS.TrustStoreFile = "../test/pki/truststore.pem"
		tlsConfig, _, _ := serverCfg.TLS.Load()

		t.Run("error - invalid TLS mode", func(t *testing.T) {
			engine := New(noop, nil)
			engine.config.InterfaceConfig.TLSMode = "oopsies"

			err := engine.Configure(*core.NewServerConfig())

			assert.EqualError(t, err, "invalid TLS mode: oopsies")
		})

		t.Run("error - TLS not configured (default interface)", func(t *testing.T) {
			engine := New(noop, nil)
			engine.config.InterfaceConfig.TLSMode = TLSServerCertMode

			err := engine.Configure(*core.NewServerConfig())

			assert.EqualError(t, err, "TLS must be enabled (without offloading) to enable it on HTTP endpoints")
		})
		t.Run("error - TLS not configured (alt interface)", func(t *testing.T) {
			engine := New(noop, nil)
			engine.config.AltBinds["alt"] = InterfaceConfig{
				TLSMode: TLSServerCertMode,
				Address: fmt.Sprintf(":%d", test.FreeTCPPort()),
			}

			err := engine.Configure(*core.NewServerConfig())

			assert.EqualError(t, err, "TLS must be enabled (without offloading) to enable it on HTTP endpoints")
		})
		t.Run("server certificate", func(t *testing.T) {
			engine := New(noop, nil)
			engine.config.InterfaceConfig.Address = fmt.Sprintf(":%d", test.FreeTCPPort())
			engine.config.InterfaceConfig.TLSMode = TLSServerCertMode

			err := engine.Configure(*serverCfg)
			require.NoError(t, err)
			err = engine.Start()
			require.NoError(t, err)
			defer engine.Shutdown()

			thisTLSConfig := tlsConfig.Clone()
			thisTLSConfig.Certificates = nil
			assertServerStarted(t, engine.config.InterfaceConfig.Address)
			assertHTTPSRequest(t, engine.config.InterfaceConfig.Address, thisTLSConfig)

			err = engine.Shutdown()
			assert.NoError(t, err)
		})
		t.Run("server and client certificate", func(t *testing.T) {
			engine := New(noop, nil)
			engine.config.InterfaceConfig.Address = fmt.Sprintf(":%d", test.FreeTCPPort())
			engine.config.InterfaceConfig.TLSMode = TLServerClientCertMode

			err := engine.Configure(*serverCfg)
			require.NoError(t, err)
			err = engine.Start()
			require.NoError(t, err)
			defer engine.Shutdown()

			assertServerStarted(t, engine.config.InterfaceConfig.Address)
			assertHTTPSRequest(t, engine.config.InterfaceConfig.Address, tlsConfig)

			// Sanity check: the same test without client certificate should fail
			thisTLSConfig := tlsConfig.Clone()
			thisTLSConfig.Certificates = nil
			_, err = doHTTPSRequest(thisTLSConfig, engine.config.InterfaceConfig.Address)
			assert.ErrorContains(t, err, "tls: bad certificate")

			err = engine.Shutdown()
			assert.NoError(t, err)
		})
	})
	t.Run("middleware", func(t *testing.T) {
		t.Run("CORS", func(t *testing.T) {
			assertHTTPHeader := func(t *testing.T, address string, headerName string, headerValue string) {
				t.Helper()
				request, _ := http.NewRequest(http.MethodOptions, "http://localhost"+address, nil)
				request.Header.Set("Origin", "example.com")
				response, err := http.DefaultClient.Do(request)
				if err != nil {
					t.Fatal(err)
				}
				assert.Equal(t, headerValue, response.Header.Get(headerName))
			}

			t.Run("enabled", func(t *testing.T) {
				engine := New(noop, nil)
				engine.config.InterfaceConfig = InterfaceConfig{
					Address: fmt.Sprintf(":%d", test.FreeTCPPort()),
					CORS: CORSConfig{
						Origin: []string{"example.com"},
					},
				}

				err := engine.Configure(*core.NewServerConfig())
				require.NoError(t, err)
				err = engine.Start()
				require.NoError(t, err)
				defer engine.Shutdown()

				assertServerStarted(t, engine.config.InterfaceConfig.Address)
				assertHTTPHeader(t, engine.config.InterfaceConfig.Address, "access-control-allow-origin", "example.com")
				assertHTTPHeader(t, engine.config.InterfaceConfig.Address, "access-control-allow-methods", "GET,HEAD,PUT,PATCH,POST,DELETE")

				err = engine.Shutdown()
				assert.NoError(t, err)
			})
			t.Run("strict mode - wildcard not allowed", func(t *testing.T) {
				engine := New(noop, nil)
				engine.config.InterfaceConfig.CORS.Origin = []string{"*"}

				err := engine.Configure(core.TestServerConfig(core.ServerConfig{Strictmode: true}))

				assert.EqualError(t, err, "wildcard CORS origin is not allowed in strict mode")
			})
			t.Run("non-strict mode - wildcard allowed", func(t *testing.T) {
				engine := New(noop, nil)
				engine.config.InterfaceConfig.CORS.Origin = []string{"*"}

				err := engine.Configure(*core.NewServerConfig())

				assert.NoError(t, err)
			})

			t.Run("not enabled in alt bind", func(t *testing.T) {
				engine := New(noop, nil)
				engine.config.InterfaceConfig = InterfaceConfig{
					Address: fmt.Sprintf(":%d", test.FreeTCPPort()),
					CORS: CORSConfig{
						Origin: []string{"test.nl"},
					},
				}
				engine.config.AltBinds["alt"] = InterfaceConfig{
					// CORS not enabled
				}

				err := engine.Configure(*core.NewServerConfig())
				require.NoError(t, err)

				engine.Router().GET("/some-other-path", func(c echo.Context) error {
					return nil
				})

				err = engine.Start()
				require.NoError(t, err)
				defer engine.Shutdown()

				assertServerStarted(t, engine.config.InterfaceConfig.Address)
				// CORS should be enabled on default path and other, but not on alt bind
				assertHTTPHeader(t, engine.config.InterfaceConfig.Address+"/", "Vary", "Origin")
				assertHTTPHeader(t, engine.config.InterfaceConfig.Address+"/some-other-path", "Vary", "Origin")
				assertNotHTTPHeader(t, engine.config.InterfaceConfig.Address+"/alt", "Vary")

				err = engine.Shutdown()
				assert.NoError(t, err)
			})
		})
		t.Run("auth", func(t *testing.T) {
			t.Run("bearer token - signing key not found", func(t *testing.T) {
				ctrl := gomock.NewController(t)
				keyResolver := crypto.NewMockKeyResolver(ctrl)
				keyResolver.EXPECT().Resolve(context.Background(), AdminTokenSigningKID).Return(nil, crypto.ErrPrivateKeyNotFound)

				engine := New(noop, keyResolver)
				engine.config.InterfaceConfig = InterfaceConfig{
					Address: fmt.Sprintf(":%d", test.FreeTCPPort()),
					Auth: AuthConfig{
						Type: BearerTokenAuth,
					},
				}
				_ = engine.Configure(*core.NewServerConfig())
				engine.Router().GET("/", func(c echo.Context) error {
					return c.String(200, "OK")
				})
				_ = engine.Start()
				defer engine.Shutdown()
				assertServerStarted(t, engine.config.InterfaceConfig.Address)

				signingKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				claims := jwt.New()
				_ = claims.Set(jwt.SubjectKey, "admin")
				_ = claims.Set(jwt.ExpirationKey, time.Now().Add(time.Hour))
				tokenBytes, _ := jwt.Sign(claims, jwa.ES256, signingKey)
				token := string(tokenBytes)

				request, _ := http.NewRequest(http.MethodGet, "http://localhost"+engine.config.InterfaceConfig.Address, nil)
				request.Header.Set("Authorization", "Bearer "+token)
				response, err := http.DefaultClient.Do(request)

				assert.NoError(t, err)
				assert.Equal(t, http.StatusUnauthorized, response.StatusCode)
			})
			t.Run("bearer token", func(t *testing.T) {
				// Create new, valid token
				signingKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				claims := jwt.New()
				_ = claims.Set(jwt.SubjectKey, "admin")
				_ = claims.Set(jwt.ExpirationKey, time.Now().Add(time.Hour))
				tokenBytes, _ := jwt.Sign(claims, jwa.ES256, signingKey)
				token := string(tokenBytes)

				// Create new, invalid token an attacker could use
				attackerSigningKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				tokenBytes, _ = jwt.Sign(claims, jwa.ES256, attackerSigningKey)
				attackerToken := string(tokenBytes)

				ctrl := gomock.NewController(t)
				keyResolver := crypto.NewMockKeyResolver(ctrl)
				keyResolver.EXPECT().Resolve(context.Background(), AdminTokenSigningKID).Return(crypto.TestKey{
					PrivateKey: signingKey,
					Kid:        AdminTokenSigningKID,
				}, nil).AnyTimes()

				engine := New(noop, keyResolver)
				engine.config.InterfaceConfig = InterfaceConfig{
					Address: fmt.Sprintf(":%d", test.FreeTCPPort()),
				}
				engine.config.AltBinds["default-with-auth"] = InterfaceConfig{
					Auth: AuthConfig{
						Type: BearerTokenAuth,
					},
				}
				engine.config.AltBinds["alt-with-auth"] = InterfaceConfig{
					Address: fmt.Sprintf(":%d", test.FreeTCPPort()),
					Auth: AuthConfig{
						Type: BearerTokenAuth,
					},
				}
				_ = engine.Configure(*core.NewServerConfig())
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
				engine.Router().GET("/", captureUser)
				engine.Router().GET("/default-with-auth", captureUser)
				engine.Router().GET("/alt-with-auth", captureUser)
				_ = engine.Start()
				defer engine.Shutdown()

				assertServerStarted(t, engine.config.InterfaceConfig.Address)

				t.Run("success - no auth on default bind root path", func(t *testing.T) {
					capturedUser = ""
					request, _ := http.NewRequest(http.MethodGet, "http://localhost"+engine.config.InterfaceConfig.Address, nil)
					response, err := http.DefaultClient.Do(request)

					assert.NoError(t, err)
					assert.Equal(t, http.StatusOK, response.StatusCode)
					assert.Empty(t, capturedUser)
				})
				t.Run("success - auth on default bind subpath path", func(t *testing.T) {
					capturedUser = ""
					request, _ := http.NewRequest(http.MethodGet, "http://localhost"+engine.config.InterfaceConfig.Address+"/default-with-auth", nil)
					request.Header.Set("Authorization", "Bearer "+token)
					response, err := http.DefaultClient.Do(request)

					assert.NoError(t, err)
					assert.Equal(t, http.StatusOK, response.StatusCode)
					assert.Equal(t, "admin", capturedUser)
				})
				t.Run("success - auth on alt bind", func(t *testing.T) {
					capturedUser = ""
					request, _ := http.NewRequest(http.MethodGet, "http://localhost"+engine.config.AltBinds["alt-with-auth"].Address+"/alt-with-auth", nil)
					request.Header.Set("Authorization", "Bearer "+token)
					response, err := http.DefaultClient.Do(request)

					assert.NoError(t, err)
					assert.Equal(t, http.StatusOK, response.StatusCode)
					assert.Equal(t, "admin", capturedUser)
				})
				t.Run("no token", func(t *testing.T) {
					capturedUser = ""
					request, _ := http.NewRequest(http.MethodGet, "http://localhost"+engine.config.InterfaceConfig.Address+"/default-with-auth", nil)
					response, err := http.DefaultClient.Do(request)

					assert.NoError(t, err)
					assert.Equal(t, http.StatusUnauthorized, response.StatusCode)
					assert.Empty(t, capturedUser)
				})
				t.Run("invalid token", func(t *testing.T) {
					capturedUser = ""
					request, _ := http.NewRequest(http.MethodGet, "http://localhost"+engine.config.InterfaceConfig.Address+"/default-with-auth", nil)
					response, err := http.DefaultClient.Do(request)
					request.Header.Set("Authorization", "Bearer invalid")

					assert.NoError(t, err)
					assert.Equal(t, http.StatusUnauthorized, response.StatusCode)
					assert.Empty(t, capturedUser)
				})
				t.Run("invalid token (incorrect signing key)", func(t *testing.T) {
					capturedUser = ""
					request, _ := http.NewRequest(http.MethodGet, "http://localhost"+engine.config.InterfaceConfig.Address+"/default-with-auth", nil)
					response, err := http.DefaultClient.Do(request)
					request.Header.Set("Authorization", "Bearer "+attackerToken)

					assert.NoError(t, err)
					assert.Equal(t, http.StatusUnauthorized, response.StatusCode)
					assert.Empty(t, capturedUser)
				})
			})
		})

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

				// Configure the default interface without authentication
				engine.config.InterfaceConfig = InterfaceConfig{
					Address: fmt.Sprintf(":%d", test.FreeTCPPort()),
					Auth: AuthConfig{
						Type:               BearerTokenAuthV2,
						AuthorizedKeysPath: authorizedKeysFile.Name(),
					},
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
				engine.Router().GET("/", captureUser)

				// Start the HTTP engine, ensuring it will be shutdown later
				_ = engine.Start()
				defer engine.Shutdown()

				// Check that the HTTP server has started listening for requests
				assertServerStarted(t, engine.config.InterfaceConfig.Address)

				// Make a test request
				t.Run("success - auth on default bind root", func(t *testing.T) {
					capturedUser = ""
					request, _ := http.NewRequest(http.MethodGet, "http://localhost"+engine.config.InterfaceConfig.Address+"/", nil)
					log.Logger().Infof("requesting %v", request.URL.String())
					request.Header.Set("Authorization", "Bearer "+string(serializedToken))
					response, err := http.DefaultClient.Do(request)

					assert.NoError(t, err)
					assert.Equal(t, http.StatusOK, response.StatusCode)
					assert.Equal(t, "random@test.local", capturedUser)
				})
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

				// Configure the default interface without authentication
				engine.config.InterfaceConfig = InterfaceConfig{
					Address: fmt.Sprintf(":%d", test.FreeTCPPort()),
				}

				// Configure an alt bind with authentication
				engine.config.AltBinds["default-with-auth"] = InterfaceConfig{
					Auth: AuthConfig{
						Type:               BearerTokenAuthV2,
						Audience:           "foo",
						AuthorizedKeysPath: authorizedKeysFile.Name(),
					},
				}

				// Configure another alt bind with authentication
				engine.config.AltBinds["alt-with-auth"] = InterfaceConfig{
					Address: fmt.Sprintf(":%d", test.FreeTCPPort()),
					Auth: AuthConfig{
						Type:               BearerTokenAuthV2,
						Audience:           "foo",
						AuthorizedKeysPath: authorizedKeysFile.Name(),
					},
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
				engine.Router().GET("/", captureUser)
				engine.Router().GET("/default-with-auth", captureUser)
				engine.Router().GET("/alt-with-auth", captureUser)

				// Start the HTTP engine, ensuring it will be shutdown later
				_ = engine.Start()
				defer engine.Shutdown()

				// Check that the HTTP server has started listening for requests
				assertServerStarted(t, engine.config.InterfaceConfig.Address)

				// Start running some tests against the server
				t.Run("success - no auth on default bind root path", func(t *testing.T) {
					capturedUser = ""
					request, _ := http.NewRequest(http.MethodGet, "http://localhost"+engine.config.InterfaceConfig.Address, nil)
					log.Logger().Infof("requesting %v", request.URL.String())
					response, err := http.DefaultClient.Do(request)

					assert.NoError(t, err)
					assert.Equal(t, http.StatusOK, response.StatusCode)
					assert.Empty(t, capturedUser)
				})
				t.Run("success - auth on default bind subpath path", func(t *testing.T) {
					capturedUser = ""
					request, _ := http.NewRequest(http.MethodGet, "http://localhost"+engine.config.InterfaceConfig.Address+"/default-with-auth", nil)
					log.Logger().Infof("requesting %v", request.URL.String())
					request.Header.Set("Authorization", "Bearer "+string(serializedToken))
					response, err := http.DefaultClient.Do(request)

					assert.NoError(t, err)
					assert.Equal(t, http.StatusOK, response.StatusCode)
					assert.Equal(t, "random@test.local", capturedUser)
				})
				t.Run("success - auth on alt bind", func(t *testing.T) {
					capturedUser = ""
					request, _ := http.NewRequest(http.MethodGet, "http://localhost"+engine.config.AltBinds["alt-with-auth"].Address+"/alt-with-auth", nil)
					log.Logger().Infof("requesting %v", request.URL.String())
					request.Header.Set("Authorization", "Bearer "+string(serializedToken))
					response, err := http.DefaultClient.Do(request)

					assert.NoError(t, err)
					assert.Equal(t, http.StatusOK, response.StatusCode)
					assert.Equal(t, "random@test.local", capturedUser)
				})
				t.Run("no token", func(t *testing.T) {
					capturedUser = ""
					request, _ := http.NewRequest(http.MethodGet, "http://localhost"+engine.config.InterfaceConfig.Address+"/default-with-auth", nil)
					log.Logger().Infof("requesting %v", request.URL.String())
					response, err := http.DefaultClient.Do(request)

					assert.NoError(t, err)
					assert.Equal(t, http.StatusUnauthorized, response.StatusCode)
					assert.Empty(t, capturedUser)
				})
				t.Run("invalid token", func(t *testing.T) {
					capturedUser = ""
					request, _ := http.NewRequest(http.MethodGet, "http://localhost"+engine.config.InterfaceConfig.Address+"/default-with-auth", nil)
					log.Logger().Infof("requesting %v", request.URL.String())
					response, err := http.DefaultClient.Do(request)
					request.Header.Set("Authorization", "Bearer invalid")

					assert.NoError(t, err)
					assert.Equal(t, http.StatusUnauthorized, response.StatusCode)
					assert.Empty(t, capturedUser)
				})
				t.Run("invalid token (incorrect signing key)", func(t *testing.T) {
					capturedUser = ""
					request, _ := http.NewRequest(http.MethodGet, "http://localhost"+engine.config.InterfaceConfig.Address+"/default-with-auth", nil)
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
		engine.config.InterfaceConfig.Address = fmt.Sprintf("localhost:%d", test.FreeTCPPort())

		err := engine.Configure(*core.NewServerConfig())
		require.NoError(t, err)

		engine.Router().GET("/some-path", func(c echo.Context) error {
			return nil
		})

		err = engine.Start()
		require.NoError(t, err)
		defer engine.Shutdown()

		assertServerStarted(t, engine.config.InterfaceConfig.Address)

		t.Run("applies default filters", func(t *testing.T) {
			// Calls to /status, ... are not logged
			for _, path := range []string{"/status", "/metrics", "/health"} {
				output.Reset()
				_, _ = http.Get("http://" + engine.config.InterfaceConfig.Address + path)
				assert.Empty(t, output.String(), path+" should not be logged")
			}
		})

		t.Run("logs requests", func(t *testing.T) {
			// Call to another, registered path is logged
			output.Reset()
			_, _ = http.Get("http://" + engine.config.InterfaceConfig.Address + "/some-path")
			assert.Contains(t, output.String(), "HTTP request")
		})
	})
	t.Run("bodyLogger", func(t *testing.T) {
		engine := New(noop, nil)
		engine.config.InterfaceConfig.Address = fmt.Sprintf("localhost:%d", test.FreeTCPPort())
		engine.config.InterfaceConfig.Log = LogMetadataAndBodyLevel

		err := engine.Configure(*core.NewServerConfig())
		require.NoError(t, err)
		engine.Router().POST("/", func(c echo.Context) error {
			return c.JSON(200, "hello, world")
		})

		err = engine.Start()
		require.NoError(t, err)
		defer engine.Shutdown()

		assertServerStarted(t, engine.config.InterfaceConfig.Address)

		t.Run("logs bodies", func(t *testing.T) {
			output.Reset()
			_, _ = http.Post("http://"+engine.config.InterfaceConfig.Address, "application/json", bytes.NewReader([]byte("{}")))
			assert.Contains(t, output.String(), "HTTP request body: {}")
			assert.Contains(t, output.String(), `HTTP response body: \"hello, world\"`)
		})
	})
}

func TestDecodeURIPath(t *testing.T) {
	rawParam := "urn:oid:2.16.840.1.113883.2.4.6.1:87654321"
	encodedParam := "urn%3Aoid%3A2.16.840.1.113883.2.4.6.1%3A87654321"

	t.Run("without middleware, it returns the encoded param", func(t *testing.T) {
		e := echo.New()
		r := e.Router()
		r.Add(http.MethodGet, "/api/:someparam", func(context echo.Context) error {
			param := context.Param("someparam")
			return context.Blob(200, "text/plain", []byte(param))
		})

		req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/%v", encodedParam), nil)
		rec := httptest.NewRecorder()
		e.ServeHTTP(rec, req)
		defer rec.Result().Body.Close()
		bodyBytes, _ := io.ReadAll(rec.Result().Body)
		assert.Equal(t, encodedParam, string(bodyBytes))
	})

	t.Run("with middleware, it return the decoded param", func(t *testing.T) {
		e := echo.New()
		r := e.Router()
		e.Use(decodeURIPath)
		r.Add(http.MethodGet, "/api/:someparam", func(context echo.Context) error {
			param := context.Param("someparam")
			return context.Blob(200, "text/plain", []byte(param))
		})

		req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/%v", encodedParam), nil)
		rec := httptest.NewRecorder()
		e.ServeHTTP(rec, req)
		defer rec.Result().Body.Close()
		bodyBytes, _ := io.ReadAll(rec.Result().Body)
		assert.Equal(t, rawParam, string(bodyBytes))
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

func assertHTTPSRequest(t *testing.T, address string, tlsConfig *tls.Config) {
	t.Helper()
	response, err := doHTTPSRequest(tlsConfig, address)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.ReadAll(response.Body)
}

func doHTTPSRequest(tlsConfig *tls.Config, address string) (*http.Response, error) {
	response, err := (&http.Client{Transport: &http.Transport{
		TLSClientConfig: tlsConfig,
	}}).Get("https://localhost" + address)
	return response, err
}

func assertHTTPRequest(t *testing.T, address string) {
	t.Helper()
	response, err := http.Get("http://localhost" + address)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.ReadAll(response.Body)
}

func assertNotHTTPHeader(t *testing.T, address string, headerName string) {
	t.Helper()
	request, _ := http.NewRequest(http.MethodGet, "http://localhost"+address, nil)
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	assert.Empty(t, response.Header.Get(headerName))
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
	jwkKey, err := jwk.New(priv)
	require.NoError(t, err)

	// Set the key ID for the jwk to be the public key fingerprint
	err = jwkKey.Set(jwk.KeyIDKey, ssh.FingerprintSHA256(sshPub))
	require.NoError(t, err)

	// Create a serializer configured to use the generated key
	serializer := jwt.NewSerializer().Sign(jwa.EdDSA, jwkKey)

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

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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"fmt"
	"github.com/golang/mock/gomock"
	"github.com/labstack/echo/v4"
	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwt"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/http/log"
	"github.com/nuts-foundation/nuts-node/test"
	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/writer"
	"github.com/stretchr/testify/assert"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestEngine_Configure(t *testing.T) {
	noop := func() {}

	t.Run("ok, no TLS (default)", func(t *testing.T) {
		engine := New(noop, nil)
		engine.config.InterfaceConfig.Address = fmt.Sprintf(":%d", test.FreeTCPPort())
		engine.config.InterfaceConfig.TLSMode = ""

		err := engine.Configure(*core.NewServerConfig())
		if !assert.NoError(t, err) {
			return
		}
		err = engine.Start()
		if !assert.NoError(t, err) {
			return
		}
		defer engine.Shutdown()

		assertHTTPRequest(t, engine.config.InterfaceConfig.Address)

		err = engine.Shutdown()
		assert.NoError(t, err)
	})
	t.Run("ok, no TLS (explicitly disabled)", func(t *testing.T) {
		engine := New(noop, nil)
		engine.config.InterfaceConfig.Address = fmt.Sprintf(":%d", test.FreeTCPPort())
		engine.config.InterfaceConfig.TLSMode = TLSDisabledMode

		err := engine.Configure(*core.NewServerConfig())
		if !assert.NoError(t, err) {
			return
		}
		err = engine.Start()
		if !assert.NoError(t, err) {
			return
		}
		defer engine.Shutdown()

		assertHTTPRequest(t, engine.config.InterfaceConfig.Address)

		err = engine.Shutdown()
		assert.NoError(t, err)
	})
	t.Run("TLS", func(t *testing.T) {
		serverCfg := core.NewServerConfig()
		serverCfg.TLS.CertFile = "../test/pki/certificate-and-key.pem"
		serverCfg.TLS.CertKeyFile = "../test/pki/certificate-and-key.pem"
		serverCfg.TLS.TrustStoreFile = "../test/pki/truststore.pem"
		tlsConfig, _ := serverCfg.TLS.Load()

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
			if !assert.NoError(t, err) {
				return
			}
			err = engine.Start()
			if !assert.NoError(t, err) {
				return
			}
			defer engine.Shutdown()

			thisTLSConfig := tlsConfig.Clone()
			thisTLSConfig.Certificates = nil
			assertHTTPSRequest(t, engine.config.InterfaceConfig.Address, thisTLSConfig)

			err = engine.Shutdown()
			assert.NoError(t, err)
		})
		t.Run("server and client certificate", func(t *testing.T) {
			engine := New(noop, nil)
			engine.config.InterfaceConfig.Address = fmt.Sprintf(":%d", test.FreeTCPPort())
			engine.config.InterfaceConfig.TLSMode = TLServerClientCertMode

			err := engine.Configure(*serverCfg)
			if !assert.NoError(t, err) {
				return
			}
			err = engine.Start()
			time.Sleep(100 * time.Millisecond)
			if !assert.NoError(t, err) {
				return
			}
			defer engine.Shutdown()

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
			t.Run("enabled", func(t *testing.T) {
				engine := New(noop, nil)
				engine.config.InterfaceConfig = InterfaceConfig{
					Address: fmt.Sprintf(":%d", test.FreeTCPPort()),
					CORS: CORSConfig{
						Origin: []string{"test.nl"},
					},
				}

				err := engine.Configure(*core.NewServerConfig())
				if !assert.NoError(t, err) {
					return
				}
				err = engine.Start()
				if !assert.NoError(t, err) {
					return
				}
				defer engine.Shutdown()

				assertHTTPHeader(t, engine.config.InterfaceConfig.Address, "Vary", "Origin")

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
				if !assert.NoError(t, err) {
					return
				}

				engine.Router().GET("/some-other-path", func(c echo.Context) error {
					return nil
				})

				err = engine.Start()
				if !assert.NoError(t, err) {
					return
				}
				defer engine.Shutdown()

				// CORS should be enabled on default path and other, but not on alt bind
				assertHTTPHeader(t, engine.config.InterfaceConfig.Address+"/", "Vary", "Origin")
				assertHTTPHeader(t, engine.config.InterfaceConfig.Address+"/some-other-path", "Vary", "Origin")
				assertNotHTTPHeader(t, engine.config.InterfaceConfig.Address+"/alt", "Vary")

				err = engine.Shutdown()
				assert.NoError(t, err)
			})
		})
		t.Run("auth", func(t *testing.T) {
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
				keyResolver.EXPECT().Resolve(AdminTokenSigningKID).Return(crypto.TestKey{
					PrivateKey: signingKey,
					Kid:        AdminTokenSigningKID,
				}, nil).AnyTimes()
				defer ctrl.Finish()

				engine := New(noop, keyResolver)
				engine.config.InterfaceConfig = InterfaceConfig{
					Address: fmt.Sprintf(":%d", test.FreeTCPPort()),
					Auth: AuthConfig{
						Type: BearerTokenAuth,
					},
				}

				_ = engine.Configure(*core.NewServerConfig())
				var capturedUser string
				engine.Router().GET("/", func(c echo.Context) error {
					capturedUser = c.Get(core.UserContextKey).(string)
					return nil
				})
				_ = engine.Start()
				defer engine.Shutdown()

				t.Run("success", func(t *testing.T) {
					capturedUser = ""
					request, _ := http.NewRequest(http.MethodGet, "http://localhost"+engine.config.InterfaceConfig.Address, nil)
					request.Header.Set("Authorization", "Bearer "+token)
					response, err := http.DefaultClient.Do(request)

					assert.NoError(t, err)
					assert.Equal(t, http.StatusOK, response.StatusCode)
					assert.Equal(t, "admin", capturedUser)
				})
				t.Run("no token", func(t *testing.T) {
					capturedUser = ""
					request, _ := http.NewRequest(http.MethodGet, "http://localhost"+engine.config.InterfaceConfig.Address, nil)
					response, err := http.DefaultClient.Do(request)

					assert.NoError(t, err)
					assert.Equal(t, http.StatusUnauthorized, response.StatusCode)
					assert.Empty(t, capturedUser)
				})
				t.Run("invalid token", func(t *testing.T) {
					capturedUser = ""
					request, _ := http.NewRequest(http.MethodGet, "http://localhost"+engine.config.InterfaceConfig.Address, nil)
					response, err := http.DefaultClient.Do(request)
					request.Header.Set("Authorization", "Bearer invalid")

					assert.NoError(t, err)
					assert.Equal(t, http.StatusUnauthorized, response.StatusCode)
					assert.Empty(t, capturedUser)
				})
				t.Run("invalid token (incorrect signing key)", func(t *testing.T) {
					capturedUser = ""
					request, _ := http.NewRequest(http.MethodGet, "http://localhost"+engine.config.InterfaceConfig.Address, nil)
					response, err := http.DefaultClient.Do(request)
					request.Header.Set("Authorization", "Bearer "+attackerToken)

					assert.NoError(t, err)
					assert.Equal(t, http.StatusUnauthorized, response.StatusCode)
					assert.Empty(t, capturedUser)
				})
			})
		})
	})
}

func TestEngine_ApplyGlobalMiddleware(t *testing.T) {
	output := new(bytes.Buffer)
	logrus.StandardLogger().AddHook(&writer.Hook{
		Writer:    output,
		LogLevels: []logrus.Level{logrus.InfoLevel, logrus.DebugLevel},
	})

	noop := func() {}

	t.Run("global middleware not applied to /status and /metrics", func(t *testing.T) {
		log.Logger()
		engine := New(noop, nil)
		engine.config.InterfaceConfig.Address = fmt.Sprintf("localhost:%d", test.FreeTCPPort())

		err := engine.Configure(*core.NewServerConfig())
		if !assert.NoError(t, err) {
			return
		}

		engine.Router().GET("/some-path", func(c echo.Context) error {
			return nil
		})

		err = engine.Start()
		if !assert.NoError(t, err) {
			return
		}
		defer engine.Shutdown()

		// Call to /status is not logged
		output.Reset()
		_, _ = http.Get("http://" + engine.config.InterfaceConfig.Address + "/status")
		assert.NotContains(t, output.String(), "HTTP request")

		// Call to another, registered path is logged
		output.Reset()
		_, _ = http.Get("http://" + engine.config.InterfaceConfig.Address + "/some-path")
		assert.Contains(t, output.String(), "HTTP request")

		err = engine.Shutdown()
		assert.NoError(t, err)
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

func assertHTTPHeader(t *testing.T, address string, headerName string, headerValue string) {
	t.Helper()
	request, _ := http.NewRequest(http.MethodGet, "http://localhost"+address, nil)
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, headerValue, response.Header.Get(headerName))
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

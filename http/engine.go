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
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/lestrrat-go/jwx/jwa"
	"github.com/nuts-foundation/nuts-node/core"
	cryptoEngine "github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/http/log"
	"github.com/nuts-foundation/nuts-node/http/tokenV2"
)

// AdminTokenSigningKID returns the KID of the signing key used to sign the admin token.
const AdminTokenSigningKID = "admin-token-signing-key"

const moduleName = "HTTP"

// New returns a new HTTP engine. The callback is called when an HTTP interface shuts down unexpectedly.
func New(serverShutdownCb func(), signingKeyResolver cryptoEngine.KeyResolver) *Engine {
	return &Engine{
		signingKeyResolver: signingKeyResolver,
		serverShutdownCb:   serverShutdownCb,
		config:             DefaultConfig(),
	}
}

// Engine is the HTTP engine.
type Engine struct {
	server             *MultiEcho
	signingKeyResolver cryptoEngine.KeyResolver
	serverShutdownCb   func()
	config             Config
}

// Router returns the router of the HTTP engine, which can be used by other engines to register HTTP handlers.
func (h Engine) Router() core.EchoRouter {
	return h.server
}

// Configure loads the configuration for the HTTP engine.
func (h *Engine) Configure(serverConfig core.ServerConfig) error {
	// Override default Echo HTTP error when bearer token is expected but not provided.
	// Echo returns "Bad Request (400)" by default, but we use this for incorrect use of API parameters.
	// "Unauthorized (401)" is a better fit.
	middleware.ErrJWTMissing = echo.NewHTTPError(http.StatusUnauthorized, "missing or malformed jwt")

	var tlsConfig *tls.Config
	var err error
	if serverConfig.TLS.Offload == core.NoOffloading {
		tlsConfig, err = serverConfig.TLS.Load()
		if err != nil {
			return err
		}
	}

	h.server = NewMultiEcho()
	log.Logger().Infof("Binding %s -> %s", RootPath, h.config.Address)
	if err = h.server.Bind(RootPath, h.config.Address, func() (EchoServer, error) {
		return h.createEchoServer(h.config.InterfaceConfig, tlsConfig)
	}); err != nil {
		return err
	}

	for httpPath, httpConfig := range h.config.AltBinds {
		address := httpConfig.Address
		if len(address) == 0 {
			address = h.config.Address
		}
		log.Logger().Infof("Binding /%s -> %s", httpPath, address)
		if err := h.server.Bind(httpPath, address, func() (EchoServer, error) {
			return h.createEchoServer(httpConfig, tlsConfig)
		}); err != nil {
			return err
		}
	}

	h.applyGlobalMiddleware(h.server, serverConfig)

	// Apply path-dependent config for configured HTTP paths
	var paths []string
	for httpPath, httpConfig := range h.config.AltBinds {
		boundServer := h.server.getInterface(httpPath)
		err := h.applyBindMiddleware(boundServer, httpPath, nil, serverConfig, httpConfig)
		if err != nil {
			return err
		}
		if !strings.HasPrefix(httpPath, "/") {
			httpPath = "/" + httpPath
		}
		paths = append(paths, httpPath)
	}

	// Apply path-dependent config for root path, but exclude configured HTTP paths to avoid enabling middleware twice.
	err = h.applyBindMiddleware(h.server.getInterface(RootPath), RootPath, paths, serverConfig, h.config.InterfaceConfig)
	if err != nil {
		return err
	}

	return nil
}

func (h *Engine) createEchoServer(cfg InterfaceConfig, tlsConfig *tls.Config) (*echoAdapter, error) {
	echoServer := echo.New()
	echoServer.HideBanner = true
	echoServer.HidePort = true

	// ErrorHandler
	echoServer.HTTPErrorHandler = core.CreateHTTPErrorHandler()

	// Reverse proxies must set the X-Forwarded-For header to the original client IP.
	echoServer.IPExtractor = echo.ExtractIPFromXFFHeader()

	var startFn func(address string) error
	switch cfg.TLSMode {
	case TLSServerCertMode:
		log.Logger().Infof("Enabling TLS for HTTP interface: %s", cfg.Address)
		fallthrough
	case TLServerClientCertMode:
		if tlsConfig == nil {
			return nil, fmt.Errorf("TLS must be enabled (without offloading) to enable it on HTTP endpoints")
		}
		serverTLSConfig := tlsConfig.Clone()
		if cfg.TLSMode == TLServerClientCertMode {
			log.Logger().Infof("Enabling TLS (with client certificate requirement) for HTTP interface: %s", cfg.Address)
			serverTLSConfig.ClientAuth = tls.RequireAndVerifyClientCert
		}
		echoServer.TLSServer.TLSConfig = serverTLSConfig
		echoServer.TLSServer.Addr = cfg.Address
		startFn = func(address string) error {
			return echoServer.StartServer(echoServer.TLSServer)
		}
	case "":
		fallthrough
	case TLSDisabledMode:
		startFn = echoServer.Start
	default:
		return nil, fmt.Errorf("invalid TLS mode: %s", cfg.TLSMode)
	}

	return &echoAdapter{
		startFn:    startFn,
		shutdownFn: echoServer.Shutdown,
		addFn:      echoServer.Add,
		useFn:      echoServer.Use,
	}, nil
}

// Name returns the name of the engine.
func (h *Engine) Name() string {
	return moduleName
}

// Config returns the configuration of the HTTP engine.
func (h *Engine) Config() interface{} {
	return &h.config
}

// Start starts the HTTP engine.
func (h *Engine) Start() error {
	go func(server *MultiEcho, cancel func()) {
		if err := server.Start(); err != nil {
			if !errors.Is(err, http.ErrServerClosed) {
				log.Logger().
					WithError(err).
					Error("HTTP server stopped due to error")
			}
		}
		cancel()
	}(h.server, h.serverShutdownCb)
	return nil
}

// Shutdown shuts down the HTTP engine.
func (h *Engine) Shutdown() error {
	return h.server.Shutdown(context.Background())
}

// decodeURIPath is echo middleware that decodes path parameters
func decodeURIPath(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		// FIXME: This is a hack because of https://github.com/labstack/echo/issues/1258
		newValues := make([]string, len(c.ParamValues()))
		for i, value := range c.ParamValues() {
			path, err := url.PathUnescape(value)
			if err != nil {
				path = value
			}
			newValues[i] = path
		}
		c.SetParamNames(c.ParamNames()...)
		c.SetParamValues(newValues...)
		return next(c)
	}
}

// matchesPath checks whether the request URI path hierarchically matches the given path.
// Examples:
// / matches /
// /foo matches /
// /foo/ matches /
// /foo/bla matches /
// /foo/bla does not match /bla
func matchesPath(requestURI string, path string) bool {
	if path == "/" {
		return true
	}
	if !strings.HasSuffix(requestURI, "/") {
		requestURI += "/"
	}
	if !strings.HasSuffix(path, "/") {
		path += "/"
	}
	return requestURI == path || strings.HasPrefix(requestURI, path)
}

func (h Engine) applyGlobalMiddleware(echoServer core.EchoRouter, serverConfig core.ServerConfig) {
	// Use middleware to decode URL encoded path parameters like did%3Anuts%3A123 -> did:nuts:123
	echoServer.Use(decodeURIPath)

	// Always enabled in strict mode
	if serverConfig.Strictmode || serverConfig.InternalRateLimiter {
		echoServer.Use(newInternalRateLimiter(map[string][]string{
			http.MethodPost: {
				"/internal/vcr/v2/issuer/vc",                   // issuing new VCs
				"/internal/vdr/v1/did",                         // creating new DIDs
				"/internal/vdr/v1/did/:did/verificationmethod", // add VM to DID
				"/internal/didman/v1/did/:did/endpoint",        // add endpoint to DID
				"/internal/didman/v1/did/:did/compoundservice", // add compound service to DID
			},
			http.MethodPut: {
				"/internal/vdr/v1/did/:did",                // updating DIDs
				"/internal/didman/v1/did/:did/contactinfo", // updating contactinfo in DID
			}}, 24*time.Hour, 3000, 30),
		)
	}
}

func (h Engine) applyBindMiddleware(echoServer EchoServer, path string, excludePaths []string, serverConfig core.ServerConfig, cfg InterfaceConfig) error {
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}

	skipper := func(c echo.Context) bool {
		if !matchesPath(c.Request().RequestURI, path) {
			return true
		}
		for _, excludePath := range excludePaths {
			if matchesPath(c.Request().RequestURI, excludePath) {
				return true
			}
		}
		return false
	}

	// Logging
	loggerSkipper := func(c echo.Context) bool {
		// Aside from interface-driven skipper, skip logging for calls to /metrics, /status, and /health
		if skipper(c) {
			return true
		}
		//
		for _, excludePath := range []string{"/metrics", "/status", "/health"} {
			if matchesPath(c.Request().RequestURI, excludePath) {
				return true
			}
		}
		return false
	}
	if cfg.Log != LogNothingLevel {
		// Log when level is set to LogMetadataLevel or LogMetadataAndBodyLevel
		echoServer.Use(requestLoggerMiddleware(loggerSkipper, log.Logger()))
	}
	if cfg.Log == LogMetadataAndBodyLevel {
		// Log when level is set to LogMetadataAndBodyLevel
		echoServer.Use(bodyLoggerMiddleware(skipper, log.Logger()))
	}

	address := h.server.getAddressForPath(path)

	// CORS
	if cfg.CORS.Enabled() {
		log.Logger().Infof("Enabling CORS for HTTP endpoint: %s%s", address, path)
		if serverConfig.Strictmode {
			for _, origin := range cfg.CORS.Origin {
				if strings.TrimSpace(origin) == "*" {
					return errors.New("wildcard CORS origin is not allowed in strict mode")
				}
			}
		}
		echoServer.Use(middleware.CORSWithConfig(middleware.CORSConfig{AllowOrigins: cfg.CORS.Origin, Skipper: skipper}))
	}

	// Auth
	switch cfg.Auth.Type {
	// Allow API endpoints without authentication
	case "":
		return nil

	// The legacy authentication middleware
	case BearerTokenAuth:
		log.Logger().Infof("Enabling token authentication for HTTP interface: %s%s", address, path)
		echoServer.Use(middleware.JWTWithConfig(middleware.JWTConfig{
			KeyFunc: func(_ *jwt.Token) (interface{}, error) {
				signingKey, err := h.signingKeyResolver.Resolve(context.Background(), AdminTokenSigningKID)
				if err == nil {
					return signingKey.Public(), nil
				}
				return nil, err
			},
			Skipper: skipper,
			SuccessHandler: func(c echo.Context) {
				// Replace user in context, which now contains the validated JWT token, with the name of the user.
				// This is easier for logging.
				token := c.Get(core.UserContextKey).(*jwt.Token)
				c.Set(core.UserContextKey, token.Claims.(jwt.MapClaims)["sub"])
			},
			ContextKey:    core.UserContextKey,
			SigningMethod: jwa.ES256.String(),
		}))

	// The V2 bearer token authentication middleware
	case BearerTokenAuthV2:
		log.Logger().Infof("Enabling token authentication (v2) for HTTP interface: %s%s", address, path)

		// Use the configured audience or the hostname by default
		audience := cfg.Auth.Audience
		if audience == "" {
			// Get the hostname of the machine
			var err error
			audience, err = os.Hostname()
			if err != nil {
				return fmt.Errorf("unable to discover hostname: %w", err)
			}
			log.Logger().Infof("Enforcing default audience: %v", audience)
		}

		// Construct the middleware using the specified audience and authorized keys file
		authenticator, err := tokenV2.NewFromFile(skipper, audience, cfg.Auth.AuthorizedKeysPath)
		if err != nil {
			return fmt.Errorf("unable to create token v2 middleware: %v", err)
		}

		// Apply the authorization middleware to the echo server
		echoServer.Use(authenticator.Handler)

	// Any other configuration value causes an error condition
	default:
		return fmt.Errorf("Unsupported authentication engine: %v", cfg.Auth.Type)
	}

	return nil
}

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
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/nuts-foundation/nuts-node/core"
	cryptoEngine "github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/http/client"
	"github.com/nuts-foundation/nuts-node/http/log"
	"github.com/nuts-foundation/nuts-node/http/tokenV2"
	"github.com/nuts-foundation/nuts-node/vdr/didnuts"
)

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
	h.configureClient(serverConfig)

	// Override default Echo HTTP error when bearer token is expected but not provided.
	// Echo returns "Bad Request (400)" by default, but we use this for incorrect use of API parameters.
	// "Unauthorized (401)" is a better fit.
	middleware.ErrJWTMissing = echo.NewHTTPError(http.StatusUnauthorized, "missing or malformed jwt")

	// We have 2 HTTP interfaces: internal and public
	// The following paths (and their subpaths) are bound to the internal interface:
	// - /internal
	// - /status
	// - /health
	// - /metrics
	// All other paths are bound to the public interface.

	h.server = NewMultiEcho()
	// Public endpoints
	if err := h.server.Bind(RootPath, h.config.Public.Address, h.createEchoServer, h.config.ClientIPHeaderName); err != nil {
		return err
	}
	// Internal endpoints
	for _, httpPath := range []string{"/internal", "/status", "/health", "/metrics"} {
		if err := h.server.Bind(httpPath, h.config.Internal.Address, h.createEchoServer, h.config.ClientIPHeaderName); err != nil {
			return err
		}
	}

	h.applyRateLimiterMiddleware(h.server, serverConfig)
	h.applyLoggerMiddleware(h.server, []string{"/metrics", "/status", "/health"}, h.config.Log)
	return h.applyAuthMiddleware(h.server, "/internal", h.config.Internal.Auth)
}

func (h *Engine) configureClient(serverConfig core.ServerConfig) {
	client.StrictMode = serverConfig.Strictmode
	// Configure the HTTP caching client, if enabled. Set it to http.DefaultTransport so it can be used by any subsystem.
	if h.config.ResponseCacheSize > 0 {
		client.DefaultCachingTransport = client.NewCachingTransport(client.SafeHttpTransport, h.config.ResponseCacheSize)
	}
}

func (h *Engine) createEchoServer(ipHeader string) (EchoServer, error) {
	echoServer := echo.New()
	echoServer.HideBanner = true
	echoServer.HidePort = true

	// ErrorHandler
	echoServer.HTTPErrorHandler = core.CreateHTTPErrorHandler()

	// Extract original client IP from configured header.
	switch ipHeader {
	case echo.HeaderXForwardedFor:
		echoServer.IPExtractor = echo.ExtractIPFromXFFHeader()
	case "":
		echoServer.IPExtractor = echo.ExtractIPDirect() // sensible fallback; use source address from IPv4/IPv6 packet header if there is no HTTP header.
	default:
		echoServer.IPExtractor = extractIPFromCustomHeader(ipHeader)
	}

	return &echoAdapter{
		startFn:    echoServer.Start,
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

func (h Engine) applyRateLimiterMiddleware(echoServer core.EchoRouter, serverConfig core.ServerConfig) {
	// Always enabled in strict mode, but only if did:nuts is enabled on the node
	if (serverConfig.Strictmode || serverConfig.InternalRateLimiter) && slices.Contains(serverConfig.DIDMethods, didnuts.MethodName) {
		echoServer.Use(newInternalRateLimiter(map[string][]string{
			http.MethodPost: {
				"/internal/vcr/v2/issuer/vc",                      // issuing new VCs
				"/internal/vdr/v1/did",                            // creating new DIDs
				"/internal/vdr/v1/did/:did/verificationmethod",    // add VM to DID
				"/internal/didman/v1/did/:did/endpoint",           // add endpoint to DID
				"/internal/didman/v1/did/:did/compoundservice",    // add compound service to DID
				"/internal/vdr/v2/subject",                        // create new subject
				"/internal/vdr/v2/subject/:id/service",            // add service to subject
				"/internal/vdr/v2/subject/:id/service/:serviceId", // update service for a subject
				"/internal/vdr/v2/subject/:id/verificationmethod", // create new verification method for subject
			},
			http.MethodPut: {
				"/internal/vdr/v1/did/:did",                // updating DIDs
				"/internal/didman/v1/did/:did/contactinfo", // updating contactinfo in DID
			}}, 24*time.Hour, 3000, 30),
		)
	}
}

func (h Engine) applyLoggerMiddleware(echoServer core.EchoRouter, excludePaths []string, logLevel LogLevel) {
	skipper := func(c echo.Context) bool {
		for _, excludePath := range excludePaths {
			if matchesPath(c.Request().RequestURI, excludePath) {
				return true
			}
		}
		return false
	}
	if logLevel != LogNothingLevel {
		// Log when level is set to LogMetadataLevel or LogMetadataAndBodyLevel
		echoServer.Use(requestLoggerMiddleware(skipper, log.Logger()))
	}
	if logLevel == LogMetadataAndBodyLevel {
		// Log when level is set to LogMetadataAndBodyLevel
		echoServer.Use(bodyLoggerMiddleware(skipper, log.Logger()))
	}
}

func (h Engine) applyAuthMiddleware(echoServer core.EchoRouter, path string, config AuthConfig) error {
	address := h.server.getAddressForPath(path)

	skipper := func(c echo.Context) bool {
		return !matchesPath(c.Request().RequestURI, path)
	}

	// Auth
	switch config.Type {
	// Allow API endpoints without authentication
	case "":
		return nil

	case BearerTokenAuthV2:
		log.Logger().Infof("Enabling token authentication (v2) for HTTP interface: %s%s", address, path)

		// Use the configured audience or the hostname by default
		audience := config.Audience
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
		authenticator, err := tokenV2.NewFromFile(skipper, audience, config.AuthorizedKeysPath)
		if err != nil {
			return fmt.Errorf("unable to create token v2 middleware: %v", err)
		}

		// Apply the authorization middleware to the echo server
		echoServer.Use(authenticator.Handler)

	// Any other configuration value causes an error condition
	default:
		return fmt.Errorf("unsupported authentication engine: %v", config.Type)
	}

	return nil
}

// extractIPFromCustomHeader extracts an IP address from any custom header.
// If the header is missing or contains an invalid IP, the extractor returns the ip from the request.
// This is an altered version of echo.ExtractIPFromRealIPHeader() that does not check for trusted IPs.
func extractIPFromCustomHeader(ipHeader string) echo.IPExtractor {
	extractIP := echo.ExtractIPDirect()
	return func(req *http.Request) string {
		directIP := extractIP(req) // source address from IPv4/IPv6 packet header
		realIP := req.Header.Get(ipHeader)
		if realIP == "" {
			return directIP
		}

		realIP = strings.TrimPrefix(realIP, "[")
		realIP = strings.TrimSuffix(realIP, "]")
		if rIP := net.ParseIP(realIP); rIP != nil {
			return realIP
		}

		return directIP
	}
}

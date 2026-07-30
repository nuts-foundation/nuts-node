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
	"github.com/nuts-foundation/nuts-node/core"
	cryptoEngine "github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/http/client"
	"github.com/nuts-foundation/nuts-node/http/log"
	"github.com/nuts-foundation/nuts-node/http/tokenV2"
	"github.com/nuts-foundation/nuts-node/tracing"
	"github.com/nuts-foundation/nuts-node/vdr/didnuts"
	"go.opentelemetry.io/contrib/instrumentation/github.com/labstack/echo/otelecho"
)

const moduleName = "HTTP"

// diagnosticsPath is the status endpoint that reports software version, git commit, peer list
// and store counts. It is only meant to be available on the internal interface, but it shares
// its first path segment with /status, which deliberately stays public as a liveness signal
// for load balancers and uptime monitors.
//
// Interface binding (MultiEcho) resolves on the first path segment only and rejects subpath
// binds, so /status and /status/diagnostics cannot be bound to different interfaces through
// the bind table: the route is registered on every interface that serves /status. Therefore
// internalOnlyMiddleware refuses requests that reach this path through any interface other
// than the internal one. If the bind table ever learns longest-prefix matching so subpaths
// can be bound to their own interface, this path should become a regular internal-only bind
// and the middleware can be removed.
const diagnosticsPath = StatusPath + "/diagnostics"

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
	if err := h.configureClient(serverConfig); err != nil {
		return err
	}

	// We have 2 HTTP interfaces: internal and public
	// The following paths (and their subpaths) are bound to the internal interface:
	// - /internal
	// - /status
	// - /health
	// - /metrics
	// All other paths are bound to the public interface.

	h.server = NewMultiEcho()
	// Public endpoints
	if err := h.server.Bind(RootPath, []string{h.config.Public.Address}, h.createEchoServer, h.config.ClientIPHeaderName); err != nil {
		return err
	}
	// Internal endpoints
	for _, httpPath := range []string{InternalPath, HealthPath, MetricsPath} {
		if err := h.server.Bind(httpPath, []string{h.config.Internal.Address}, h.createEchoServer, h.config.ClientIPHeaderName); err != nil {
			return err
		}
	}
	// /status endpoint is both on internally and publicly available.
	if err := h.server.Bind(StatusPath, []string{h.config.Public.Address, h.config.Internal.Address}, h.createEchoServer, h.config.ClientIPHeaderName); err != nil {
		return err
	}

	h.applyTracingMiddleware(h.server)
	h.applyRateLimiterMiddleware(h.server, serverConfig)
	h.applyLoggerMiddleware(h.server, []string{MetricsPath, StatusPath, HealthPath}, h.config.Log)
	diagnosticsGuard, err := internalOnlyMiddleware(h.config.Internal.Address, diagnosticsPath)
	if err != nil {
		return err
	}
	h.server.Use(diagnosticsGuard)
	return h.applyAuthMiddleware(h.server, InternalPath, h.config.Internal.Auth)
}

// internalOnlyMiddleware returns middleware that refuses requests to the given path (and its
// subpaths) unless the connection was accepted on the interface the internal API is bound to.
//
// How the interface is determined: Go's net/http server stores the connection's local address
// (the address the listener accepted on) in the request context under http.LocalAddrContextKey.
// Every HTTP interface listens on its own port, since binding the same port twice fails at
// startup, so comparing the local address port against the internal interface's configured
// port identifies the interface the request arrived on. When the operator configures the
// public and internal interface to the same address there is only one server and the ports
// always match, which honors that (explicitly configured) setup. The comparison uses only the
// port, not the host: the configured bind host (e.g. ":8081" or "0.0.0.0:8081") does not have
// to equal the connection's concrete local IP.
//
// Requests are refused with 403 rather than 404: the endpoint's existence is public knowledge
// (the node is open source), so a 404 would hide nothing from an attacker, while the explicit
// message tells an operator whose external monitor probes this path exactly why it broke.
// When the local address is missing from the request context or unparseable, the request is
// refused (fail closed); this cannot happen with Go's net/http server, which always sets it.
func internalOnlyMiddleware(internalAddress string, path string) (echo.MiddlewareFunc, error) {
	_, internalPort, err := net.SplitHostPort(internalAddress)
	if err != nil {
		return nil, fmt.Errorf("invalid internal address %s: %w", internalAddress, err)
	}
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			if !matchesPath(c.Request().URL.Path, path) {
				return next(c)
			}
			if localAddr, ok := c.Request().Context().Value(http.LocalAddrContextKey).(net.Addr); ok {
				if _, port, err := net.SplitHostPort(localAddr.String()); err == nil && port == internalPort {
					return next(c)
				}
			}
			return echo.NewHTTPError(http.StatusForbidden, "only available on the internal interface")
		}
	}, nil
}

func (h *Engine) configureClient(serverConfig core.ServerConfig) error {
	client.StrictMode = serverConfig.Strictmode
	if err := client.SetAllowedNonPublicCIDRs(h.config.Client.AllowedInternalCIDRs); err != nil {
		return err
	}
	if err := client.SetDeniedCIDRs(h.config.Client.DeniedCIDRs); err != nil {
		return err
	}
	// Configure the HTTP caching client, if enabled. Set it to http.DefaultTransport so it can be used by any subsystem.
	if h.config.ResponseCacheSize > 0 {
		client.DefaultCachingTransport = client.NewCachingTransport(client.SafeHttpTransport, h.config.ResponseCacheSize)
	}
	return nil
}

func (h *Engine) applyTracingMiddleware(echoServer core.EchoRouter) {
	// Only apply tracing middleware if tracing is enabled
	if !tracing.Enabled() {
		return
	}
	skipper := func(c echo.Context) bool {
		// Skip health/metrics/status endpoints to reduce noise
		path := c.Request().URL.Path
		return matchesPath(path, HealthPath) || matchesPath(path, MetricsPath) || matchesPath(path, StatusPath)
	}
	echoServer.Use(otelecho.Middleware(moduleName,
		otelecho.WithSkipper(skipper),
		otelecho.WithTracerProvider(tracing.GetTracerProvider()),
	))
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
	skipper := func(c echo.Context) bool {
		return !matchesPath(c.Request().RequestURI, path)
	}

	// Auth
	switch config.Type {
	// Allow API endpoints without authentication
	case "":
		return nil

	case BearerTokenAuthV2:
		for _, address := range h.server.getAddressesForPath(path) {
			log.Logger().Infof("Enabling token authentication (v2) for HTTP interface: %s%s", address, path)
		}

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

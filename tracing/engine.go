/*
 * Nuts node
 * Copyright (C) 2026 Nuts community
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

package tracing

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/nuts-foundation/nuts-node/core"
	"github.com/sirupsen/logrus"
	"go.opentelemetry.io/contrib/bridges/otellogrus"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploghttp"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/log"
	"go.opentelemetry.io/otel/sdk/resource"
	"go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
	oteltrace "go.opentelemetry.io/otel/trace"
)

const (
	moduleName         = "Tracing"
	defaultServiceName = "nuts-node"
)

// enabled is set to true when OpenTelemetry tracing is configured.
var enabled atomic.Bool

// nutsTracerProvider holds nuts-node's own TracerProvider.
// This is used instead of the global when nuts-node is embedded in another application.
// Uses atomic.Pointer for thread-safe access during shutdown.
var nutsTracerProvider atomic.Pointer[trace.TracerProvider]

// registerAuditLogHook is a function that registers a logrus hook with the audit logger.
// It is set by the audit package during init() to avoid circular imports.
// Go guarantees imported packages initialize before the importing package, so audit's init()
// runs after tracing's package-level vars are initialized but before Configure().
var registerAuditLogHook func(hook logrus.Hook) = func(logrus.Hook) {}

// RegisterAuditLogHook sets the function that registers a logrus hook with the audit logger.
// This is called by the audit package during initialization to avoid circular imports.
func RegisterAuditLogHook(fn func(hook logrus.Hook)) {
	registerAuditLogHook = fn
}

// New creates a new tracing engine instance.
func New() *Engine {
	return &Engine{}
}

// Engine is the engine that manages OpenTelemetry tracing.
// It must be registered first to ensure tracing is active before other engines start,
// and shut down last (due to reverse shutdown order) to capture all logs/spans.
type Engine struct {
	config   Config
	shutdown func(context.Context) error
}

// Name returns the engine name.
func (e *Engine) Name() string {
	return moduleName
}

// Config returns the engine configuration.
func (e *Engine) Config() any {
	return &e.config
}

// Configure sets up OpenTelemetry tracing with the configured endpoint.
func (e *Engine) Configure(_ core.ServerConfig) error {
	shutdown, err := setupTracing(e.config)
	if err != nil {
		return fmt.Errorf("failed to setup tracing: %w", err)
	}
	e.shutdown = shutdown
	return nil
}

// Start is a no-op since tracing is already active after Configure.
func (e *Engine) Start() error {
	return nil
}

// Shutdown stops the tracing exporters and flushes any remaining spans/logs.
// Hooks remain registered but become no-ops after the OTEL providers are shut down.
func (e *Engine) Shutdown() error {
	// Reset global state
	enabled.Store(false)
	nutsTracerProvider.Store(nil)
	core.TracingHTTPTransport = nil

	// Call the shutdown function to flush and close exporters with timeout.
	// After this, any hook calls to logger.Emit() become no-ops per OTEL spec.
	if e.shutdown != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		return e.shutdown(ctx)
	}
	return nil
}

// CheckHealth returns the health status of the tracing subsystem.
// When tracing is not configured or not running, no health entry is returned (not applicable).
// When enabled and running, we return UP since we successfully initialized - we can't easily
// verify OTLP endpoint connectivity as spans are exported asynchronously.
func (e *Engine) CheckHealth() map[string]core.Health {
	if e.config.Endpoint == "" || !enabled.Load() {
		// Tracing is not configured or not running, don't report health
		return nil
	}
	// Tracing is configured and running
	return map[string]core.Health{
		"otlp": {
			Status:  core.HealthStatusUp,
			Details: e.config.Endpoint,
		},
	}
}

// Diagnostics returns diagnostic information about the tracing configuration.
func (e *Engine) Diagnostics() []core.DiagnosticResult {
	isEnabled := e.config.Endpoint != ""
	return []core.DiagnosticResult{
		core.DiagnosticResultMap{
			Title: "tracing",
			Items: []core.DiagnosticResult{
				core.GenericDiagnosticResult{Title: "enabled", Outcome: isEnabled},
				core.GenericDiagnosticResult{Title: "endpoint", Outcome: e.config.Endpoint},
				core.GenericDiagnosticResult{Title: "service_name", Outcome: e.resolvedServiceName()},
				core.GenericDiagnosticResult{Title: "insecure", Outcome: e.config.Insecure},
			},
		},
	}
}

func (e *Engine) resolvedServiceName() string {
	if e.config.ServiceName != "" {
		return e.config.ServiceName
	}
	return defaultServiceName
}

// Enabled returns true if OpenTelemetry tracing is configured.
func Enabled() bool {
	return enabled.Load()
}

// SetEnabled sets the tracing enabled flag.
// Exported for testing only; do not call from production code.
func SetEnabled(value bool) {
	enabled.Store(value)
}

// GetTracerProvider returns nuts-node's TracerProvider.
// This should be used by nuts-node components instead of otel.GetTracerProvider()
// to ensure spans are attributed to "nuts-node" service.
func GetTracerProvider() oteltrace.TracerProvider {
	if provider := nutsTracerProvider.Load(); provider != nil {
		return provider
	}
	return otel.GetTracerProvider()
}

// setupTracing initializes OpenTelemetry tracing with the given configuration.
// Returns a shutdown function that should be called on application exit.
// If cfg.Endpoint is empty, tracing is disabled and a no-op shutdown function is returned.
// When a parent TracerProvider exists (embedded mode), nuts-node uses the parent's OTEL
// infrastructure and only sets up the HTTP transport wrapper for internal API calls.
// When standalone, tracing is fully configured with OTLP exporters for traces and logs.
func setupTracing(cfg Config) (shutdown func(context.Context) error, err error) {
	if cfg.Endpoint == "" {
		logrus.Info("Tracing disabled (no endpoint configured)")
		return func(context.Context) error { return nil }, nil
	}

	// Check for parent TracerProvider first, before modifying any global state.
	// Per OpenTelemetry best practices, libraries should use the application's infrastructure,
	// not create their own. We detect embedding by checking if a SDK TracerProvider is set.
	// Note: Custom TracerProvider implementations won't be detected, but we won't overwrite
	// the global provider, so they'll continue to work.
	_, isEmbedded := otel.GetTracerProvider().(*trace.TracerProvider)

	if isEmbedded {
		return setupEmbeddedTracing()
	}
	return setupStandaloneTracing(cfg)
}

// setupEmbeddedTracing configures tracing when nuts-node is embedded in another application.
// In this mode, nuts-node reuses the parent's TracerProvider, propagator, and error handler.
// All component tracing (GORM, HTTP server/client, etc.) still works because they call
// GetTracerProvider(), which returns the parent's provider when nutsTracerProvider is nil.
// This function only needs to set up the HTTP transport wrapper and logrus hook.
func setupEmbeddedTracing() (func(context.Context) error, error) {
	enabled.Store(true)
	setupHTTPTransport()

	// Add trace context hook to inject trace_id/span_id into log entries.
	// This works with any TracerProvider and doesn't require OTLP export.
	traceContextHook := &tracingLogrusHook{}
	logrus.AddHook(traceContextHook)
	registerAuditLogHook(traceContextHook)

	logrus.Info("Tracing enabled (embedded mode, using parent's TracerProvider)")

	return func(context.Context) error { return nil }, nil
}

// setupHTTPTransport configures the HTTP transport wrapper for internal API calls.
// Uses GetTracerProvider() so it works in both embedded and standalone modes.
func setupHTTPTransport() {
	core.TracingHTTPTransport = func(transport http.RoundTripper) http.RoundTripper {
		return otelhttp.NewTransport(transport,
			otelhttp.WithTracerProvider(GetTracerProvider()),
			otelhttp.WithSpanNameFormatter(func(_ string, r *http.Request) string {
				return "internal-api: " + r.Method + " " + r.URL.Path
			}))
	}
}

// setupStandaloneTracing configures full OTEL infrastructure when running standalone.
// Sets up trace exporter, log exporter, propagator, error handler, and logrus hooks.
func setupStandaloneTracing(cfg Config) (shutdown func(context.Context) error, err error) {
	enabled.Store(true)

	ctx := context.Background()
	var shutdownFuncs []func(context.Context) error

	shutdown = func(ctx context.Context) error {
		var errs error
		for _, fn := range shutdownFuncs {
			if err := fn(ctx); err != nil {
				errs = errors.Join(errs, err)
			}
		}
		return errs
	}

	handleErr := func(err error) (func(context.Context) error, error) {
		enabled.Store(false)
		shutdownCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		shutdownErr := shutdown(shutdownCtx)
		return nil, errors.Join(err, shutdownErr)
	}

	// Set up OpenTelemetry error handler
	otel.SetErrorHandler(otel.ErrorHandlerFunc(func(err error) {
		logrus.WithError(err).Error("OpenTelemetry SDK error")
	}))

	// Set up propagator (W3C Trace Context + Baggage)
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))

	// Set up resource with service info
	serviceName := cfg.ServiceName
	if serviceName == "" {
		serviceName = defaultServiceName
	}
	version := core.Version()
	res, err := resource.New(ctx,
		resource.WithAttributes(
			semconv.ServiceNameKey.String(serviceName),
			semconv.ServiceVersionKey.String(version),
		),
	)
	if err != nil {
		return handleErr(err)
	}

	// Set up OTLP trace exporter
	traceOpts := []otlptracehttp.Option{
		otlptracehttp.WithEndpoint(cfg.Endpoint),
	}
	if cfg.Insecure {
		traceOpts = append(traceOpts, otlptracehttp.WithInsecure())
	}
	traceExporter, err := otlptracehttp.New(ctx, traceOpts...)
	if err != nil {
		return handleErr(err)
	}
	shutdownFuncs = append(shutdownFuncs, traceExporter.Shutdown)

	// Set up trace provider
	tracerProvider := trace.NewTracerProvider(
		trace.WithBatcher(traceExporter),
		trace.WithResource(res),
	)
	shutdownFuncs = append(shutdownFuncs, tracerProvider.Shutdown)

	nutsTracerProvider.Store(tracerProvider)
	otel.SetTracerProvider(tracerProvider)
	setupHTTPTransport()

	// Set up OTLP log exporter
	logOpts := []otlploghttp.Option{
		otlploghttp.WithEndpoint(cfg.Endpoint),
	}
	if cfg.Insecure {
		logOpts = append(logOpts, otlploghttp.WithInsecure())
	}
	logExporter, err := otlploghttp.New(ctx, logOpts...)
	if err != nil {
		return handleErr(err)
	}
	shutdownFuncs = append(shutdownFuncs, logExporter.Shutdown)

	// Set up log provider
	loggerProvider := log.NewLoggerProvider(
		log.WithProcessor(log.NewBatchProcessor(logExporter)),
		log.WithResource(res),
	)
	shutdownFuncs = append(shutdownFuncs, loggerProvider.Shutdown)

	// Create hooks for log correlation and OTLP export
	traceContextHook := &tracingLogrusHook{}
	otelHook := otellogrus.NewHook(serviceName, otellogrus.WithLoggerProvider(loggerProvider))

	logrus.AddHook(traceContextHook)
	logrus.AddHook(otelHook)
	registerAuditLogHook(traceContextHook)
	registerAuditLogHook(otelHook)

	logrus.WithFields(logrus.Fields{
		"endpoint": cfg.Endpoint,
		"service":  serviceName,
		"version":  version,
	}).Info("OpenTelemetry tracing initialized")

	return shutdown, nil
}

// tracingLogrusHook is a logrus hook that injects trace context into log entries.
type tracingLogrusHook struct{}

func (h *tracingLogrusHook) Levels() []logrus.Level {
	return logrus.AllLevels
}

func (h *tracingLogrusHook) Fire(entry *logrus.Entry) error {
	if !enabled.Load() || entry.Context == nil {
		return nil
	}
	span := oteltrace.SpanFromContext(entry.Context)
	if !span.SpanContext().IsValid() {
		return nil
	}
	spanCtx := span.SpanContext()
	entry.Data["trace_id"] = spanCtx.TraceID().String()
	entry.Data["span_id"] = spanCtx.SpanID().String()
	return nil
}

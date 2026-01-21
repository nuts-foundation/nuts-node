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
var nutsTracerProvider *trace.TracerProvider

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
	nutsTracerProvider = nil
	core.TracingHTTPTransport = nil

	// Call the shutdown function to flush and close exporters
	// After this, any hook calls to logger.Emit() become no-ops per OTEL spec.
	if e.shutdown != nil {
		return e.shutdown(context.Background())
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
	if nutsTracerProvider != nil {
		return nutsTracerProvider
	}
	return otel.GetTracerProvider()
}

// setupTracing initializes OpenTelemetry tracing with the given configuration.
// Returns a shutdown function that should be called on application exit.
// If cfg.Endpoint is empty, tracing is disabled and a no-op shutdown function is returned.
// When tracing is enabled, logs are sent to both stdout and the OTLP endpoint.
func setupTracing(cfg Config) (shutdown func(context.Context) error, err error) {
	if cfg.Endpoint == "" {
		logrus.Info("Tracing disabled (no endpoint configured)")
		return func(context.Context) error { return nil }, nil
	}

	// Enable tracing flag for HTTP clients and other components
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

	// Handle errors by cleaning up already-created resources
	handleErr := func(err error) (func(context.Context) error, error) {
		enabled.Store(false)
		shutdownCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		_ = shutdown(shutdownCtx)
		return nil, err
	}

	// Set up OpenTelemetry error handler to integrate with logrus
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

	// Set up OTLP HTTP exporter
	opts := []otlptracehttp.Option{
		otlptracehttp.WithEndpoint(cfg.Endpoint),
	}
	if cfg.Insecure {
		opts = append(opts, otlptracehttp.WithInsecure())
	}
	traceExporter, err := otlptracehttp.New(ctx, opts...)
	if err != nil {
		return handleErr(err)
	}
	shutdownFuncs = append(shutdownFuncs, traceExporter.Shutdown)

	// Set up trace provider with batch exporter
	tracerProvider := trace.NewTracerProvider(
		trace.WithBatcher(traceExporter),
		trace.WithResource(res),
	)
	shutdownFuncs = append(shutdownFuncs, tracerProvider.Shutdown)

	// Store nuts-node's provider for use by GetTracerProvider()
	nutsTracerProvider = tracerProvider

	// Only set as global if no other provider exists (i.e., not embedded).
	// When embedded, the parent application owns the global provider.
	_, hasParentProvider := otel.GetTracerProvider().(*trace.TracerProvider)
	if !hasParentProvider {
		otel.SetTracerProvider(tracerProvider)
	}

	// Set up HTTP transport wrapper for core package (avoids circular import)
	core.TracingHTTPTransport = func(transport http.RoundTripper) http.RoundTripper {
		return otelhttp.NewTransport(transport,
			otelhttp.WithTracerProvider(tracerProvider),
			otelhttp.WithSpanNameFormatter(func(_ string, r *http.Request) string {
				return "internal-api: " + r.Method + " " + r.URL.Path
			}))
	}

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
	// Uses official otellogrus bridge: https://pkg.go.dev/go.opentelemetry.io/contrib/bridges/otellogrus
	traceContextHook := &tracingLogrusHook{}
	otelHook := otellogrus.NewHook(serviceName, otellogrus.WithLoggerProvider(loggerProvider))

	// Add hooks to standard logger (logs go to both stdout and OTLP)
	logrus.AddHook(traceContextHook)
	logrus.AddHook(otelHook)

	// Register same hooks with audit logger (which uses its own logger instance)
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
	if entry.Context == nil {
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

/*
 * Nuts node
 * Copyright (C) 2025 Nuts community
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

package core

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/sirupsen/logrus"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploghttp"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	otellog "go.opentelemetry.io/otel/log"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/log"
	"go.opentelemetry.io/otel/sdk/resource"
	"go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
	oteltrace "go.opentelemetry.io/otel/trace"
)

const serviceName = "nuts-node"

// tracingEnabled is set to true when OpenTelemetry tracing is configured.
var tracingEnabled atomic.Bool

// TracingEnabled returns true if OpenTelemetry tracing is configured.
func TracingEnabled() bool {
	return tracingEnabled.Load()
}

// SetTracingEnabled sets the tracing enabled flag.
// Exported for testing only; do not call from production code.
func SetTracingEnabled(enabled bool) {
	tracingEnabled.Store(enabled)
}

// RegisterAuditLogHook is a function that registers a logrus hook with the audit logger.
// It is set by the audit package during initialization to avoid circular imports.
var RegisterAuditLogHook func(hook logrus.Hook) = func(logrus.Hook) {}

// SetupTracing initializes OpenTelemetry tracing with the given configuration.
// Returns a shutdown function that should be called on application exit.
// If cfg.Endpoint is empty, tracing is disabled and a no-op shutdown function is returned.
// When tracing is enabled, logs are sent to both stdout and the OTLP endpoint.
func SetupTracing(cfg TracingConfig) (shutdown func(context.Context) error, err error) {
	if cfg.Endpoint == "" {
		logrus.Info("Tracing disabled (no endpoint configured)")
		return func(context.Context) error { return nil }, nil
	}

	// Enable tracing flag for HTTP clients and other components
	tracingEnabled.Store(true)

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
	version := Version()
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
	otel.SetTracerProvider(tracerProvider)

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

	// Create OTEL hook for sending logs via OTLP (logs go to both stdout and OTLP)
	otelHook := &OtelLogrusHook{logger: loggerProvider.Logger(serviceName)}
	logrus.AddHook(otelHook)

	// Also add trace context to stdout logs
	logrus.AddHook(&tracingLogrusHook{})

	// Register hook with audit logger (which uses its own logger instance)
	RegisterAuditLogHook(otelHook)

	logrus.WithFields(logrus.Fields{
		"endpoint": cfg.Endpoint,
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

// OtelLogrusHook is a logrus hook that sends logs to an OTLP endpoint.
// It is exported so other loggers (like the audit logger) can use it.
type OtelLogrusHook struct {
	logger otellog.Logger
}

func (h *OtelLogrusHook) Levels() []logrus.Level {
	return logrus.AllLevels
}

func (h *OtelLogrusHook) Fire(entry *logrus.Entry) error {
	ctx := entry.Context
	if ctx == nil {
		ctx = context.Background()
	}

	// Convert logrus level to otel severity
	var severity otellog.Severity
	switch entry.Level {
	case logrus.TraceLevel:
		severity = otellog.SeverityTrace
	case logrus.DebugLevel:
		severity = otellog.SeverityDebug
	case logrus.InfoLevel:
		severity = otellog.SeverityInfo
	case logrus.WarnLevel:
		severity = otellog.SeverityWarn
	case logrus.ErrorLevel:
		severity = otellog.SeverityError
	case logrus.FatalLevel, logrus.PanicLevel:
		severity = otellog.SeverityFatal
	default:
		severity = otellog.SeverityInfo
	}

	// Build log record
	record := otellog.Record{}
	record.SetTimestamp(entry.Time)
	record.SetSeverity(severity)
	record.SetBody(otellog.StringValue(entry.Message))

	// Add logrus fields as attributes
	attrs := make([]otellog.KeyValue, 0, len(entry.Data))
	for k, v := range entry.Data {
		attrs = append(attrs, otellog.String(k, formatValue(v)))
	}
	record.AddAttributes(attrs...)

	h.logger.Emit(ctx, record)
	return nil
}

func formatValue(v any) string {
	if err, ok := v.(error); ok {
		return err.Error()
	}
	return fmt.Sprintf("%v", v)
}

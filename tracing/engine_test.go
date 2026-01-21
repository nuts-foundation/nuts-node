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
	"net/http"
	"testing"

	"github.com/nuts-foundation/nuts-node/core"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"
)

// resetGlobalState resets global state for test isolation.
func resetGlobalState() {
	enabled.Store(false)
	nutsTracerProvider = nil
	core.TracingHTTPTransport = nil
}

func TestSetupTracing(t *testing.T) {
	t.Run("disabled when endpoint is empty", func(t *testing.T) {
		resetGlobalState()
		t.Cleanup(resetGlobalState)
		cfg := Config{Endpoint: ""}

		shutdown, err := setupTracing(cfg)

		require.NoError(t, err)
		assert.NotNil(t, shutdown)
		assert.False(t, Enabled(), "tracing should not be enabled when endpoint is empty")
		assert.Nil(t, nutsTracerProvider, "provider should not be set when disabled")
		assert.Nil(t, core.TracingHTTPTransport, "HTTP transport should not be set when disabled")
		// Shutdown should be a no-op
		assert.NoError(t, shutdown(context.Background()))
	})

	t.Run("enabled when endpoint is configured", func(t *testing.T) {
		resetGlobalState()
		t.Cleanup(resetGlobalState)
		cfg := Config{
			Endpoint: "localhost:4318",
			Insecure: true,
		}

		shutdown, err := setupTracing(cfg)

		require.NoError(t, err)
		require.NotNil(t, shutdown)
		t.Cleanup(func() { _ = shutdown(context.Background()) })

		// Verify global state is set up correctly
		assert.True(t, Enabled(), "tracing should be enabled")
		assert.NotNil(t, nutsTracerProvider, "provider should be set")
		assert.NotNil(t, core.TracingHTTPTransport, "HTTP transport should be set")

		// Verify HTTP transport wrapper works
		wrappedTransport := core.TracingHTTPTransport(http.DefaultTransport)
		assert.NotNil(t, wrappedTransport)
		assert.NotEqual(t, http.DefaultTransport, wrappedTransport, "transport should be wrapped")
	})

}

func TestGetTracerProvider(t *testing.T) {
	t.Run("returns global provider when nutsTracerProvider is nil", func(t *testing.T) {
		originalProvider := nutsTracerProvider
		t.Cleanup(func() { nutsTracerProvider = originalProvider })

		nutsTracerProvider = nil

		provider := GetTracerProvider()
		assert.NotNil(t, provider)
	})

	t.Run("returns nuts provider when set", func(t *testing.T) {
		originalProvider := nutsTracerProvider
		t.Cleanup(func() { nutsTracerProvider = originalProvider })

		customProvider := sdktrace.NewTracerProvider()
		nutsTracerProvider = customProvider

		provider := GetTracerProvider()
		assert.Equal(t, customProvider, provider, "should return nuts-node's provider when set")
	})
}

func TestTracingLogrusHook(t *testing.T) {
	t.Run("no-op when context is nil", func(t *testing.T) {
		hook := &tracingLogrusHook{}
		entry := &logrus.Entry{
			Data: make(logrus.Fields),
		}
		err := hook.Fire(entry)
		assert.NoError(t, err)
		assert.NotContains(t, entry.Data, "trace_id")
		assert.NotContains(t, entry.Data, "span_id")
	})

	t.Run("no-op when span context is invalid", func(t *testing.T) {
		hook := &tracingLogrusHook{}
		entry := &logrus.Entry{
			Context: context.Background(),
			Data:    make(logrus.Fields),
		}
		err := hook.Fire(entry)
		assert.NoError(t, err)
		assert.NotContains(t, entry.Data, "trace_id")
		assert.NotContains(t, entry.Data, "span_id")
	})

	t.Run("adds trace context when span is valid", func(t *testing.T) {
		hook := &tracingLogrusHook{}
		// Create a valid span context
		traceID, _ := trace.TraceIDFromHex("0102030405060708090a0b0c0d0e0f10")
		spanID, _ := trace.SpanIDFromHex("0102030405060708")
		spanCtx := trace.NewSpanContext(trace.SpanContextConfig{
			TraceID:    traceID,
			SpanID:     spanID,
			TraceFlags: trace.FlagsSampled,
		})

		// Use noop tracer but with our span context
		ctx := trace.ContextWithSpanContext(context.Background(), spanCtx)

		entry := &logrus.Entry{
			Context: ctx,
			Data:    make(logrus.Fields),
		}
		err := hook.Fire(entry)
		assert.NoError(t, err)
		assert.Equal(t, "0102030405060708090a0b0c0d0e0f10", entry.Data["trace_id"])
		assert.Equal(t, "0102030405060708", entry.Data["span_id"])
	})
}

func TestEngine(t *testing.T) {
	t.Run("Name", func(t *testing.T) {
		engine := New()
		assert.Equal(t, "Tracing", engine.Name())
	})

	t.Run("Config returns pointer to config", func(t *testing.T) {
		engine := New()
		cfg := engine.Config()
		assert.IsType(t, &Config{}, cfg)
	})

	t.Run("Configure with empty endpoint", func(t *testing.T) {
		engine := New()
		engine.config = Config{Endpoint: ""}

		err := engine.Configure(core.ServerConfig{})
		assert.NoError(t, err)
	})

	t.Run("Start is a no-op", func(t *testing.T) {
		engine := New()
		err := engine.Start()
		assert.NoError(t, err)
	})

	t.Run("Shutdown when not configured", func(t *testing.T) {
		engine := New()
		err := engine.Shutdown()
		assert.NoError(t, err)
	})

	t.Run("CheckHealth when not configured returns nil", func(t *testing.T) {
		resetGlobalState()
		t.Cleanup(resetGlobalState)
		engine := New()
		engine.config = Config{Endpoint: ""}

		health := engine.CheckHealth()
		assert.Nil(t, health, "should not report health when tracing is not configured")
	})

	t.Run("CheckHealth when configured but not running returns nil", func(t *testing.T) {
		resetGlobalState()
		t.Cleanup(resetGlobalState)
		// Endpoint is configured but enabled flag is false (e.g., after shutdown)
		engine := New()
		engine.config = Config{Endpoint: "localhost:4318"}

		health := engine.CheckHealth()
		assert.Nil(t, health, "should not report health when tracing is not running")
	})

	t.Run("CheckHealth when configured and running", func(t *testing.T) {
		resetGlobalState()
		t.Cleanup(resetGlobalState)
		enabled.Store(true) // Simulate running state
		engine := New()
		engine.config = Config{Endpoint: "localhost:4318"}

		health := engine.CheckHealth()
		require.NotNil(t, health)
		assert.Equal(t, core.HealthStatusUp, health["otlp"].Status)
		assert.Equal(t, "localhost:4318", health["otlp"].Details)
	})

	t.Run("Diagnostics", func(t *testing.T) {
		engine := New()
		engine.config = Config{
			Endpoint:    "localhost:4318",
			ServiceName: "test-service",
			Insecure:    true,
		}

		results := engine.Diagnostics()
		require.Len(t, results, 1)
		assert.Equal(t, "tracing", results[0].Name())

		resultMap := results[0].Result().(map[string]interface{})
		assert.Equal(t, true, resultMap["enabled"])
		assert.Equal(t, "localhost:4318", resultMap["endpoint"])
		assert.Equal(t, "test-service", resultMap["service_name"])
		assert.Equal(t, true, resultMap["insecure"])
	})

	t.Run("Diagnostics with default service name", func(t *testing.T) {
		engine := New()
		engine.config = Config{
			Endpoint: "localhost:4318",
		}

		results := engine.Diagnostics()
		resultMap := results[0].Result().(map[string]interface{})
		assert.Equal(t, "nuts-node", resultMap["service_name"])
	})

	t.Run("Shutdown resets global state", func(t *testing.T) {
		resetGlobalState()
		t.Cleanup(resetGlobalState)

		// Simulate enabled state with all global variables set
		enabled.Store(true)
		nutsTracerProvider = sdktrace.NewTracerProvider()
		core.TracingHTTPTransport = func(rt http.RoundTripper) http.RoundTripper { return rt }

		engine := New()
		err := engine.Shutdown()

		assert.NoError(t, err)
		assert.False(t, Enabled(), "enabled should be false after shutdown")
		assert.Nil(t, nutsTracerProvider, "nutsTracerProvider should be nil after shutdown")
		assert.Nil(t, core.TracingHTTPTransport, "TracingHTTPTransport should be nil after shutdown")
	})
}

func TestRegisterAuditLogHook(t *testing.T) {
	t.Run("callback is invoked when hook is registered", func(t *testing.T) {
		// Save original and restore after test
		originalCallback := registerAuditLogHook
		t.Cleanup(func() { registerAuditLogHook = originalCallback })

		var registeredHook logrus.Hook

		// Simulate what audit.init() does
		RegisterAuditLogHook(func(hook logrus.Hook) {
			registeredHook = hook
		})

		// Simulate registering a hook (what setupTracing does)
		testHook := &tracingLogrusHook{}
		registerAuditLogHook(testHook)

		assert.Equal(t, testHook, registeredHook)
	})
}

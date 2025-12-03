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
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/trace"
)

func TestSetupTracing(t *testing.T) {
	t.Run("disabled when endpoint is empty", func(t *testing.T) {
		cfg := TracingConfig{Endpoint: ""}

		shutdown, err := SetupTracing(cfg)

		require.NoError(t, err)
		assert.NotNil(t, shutdown)
		// Shutdown should be a no-op
		assert.NoError(t, shutdown(context.Background()))
	})
}

func TestTracingLogrusHook(t *testing.T) {
	hook := &tracingLogrusHook{}

	t.Run("no-op when context is nil", func(t *testing.T) {
		entry := &logrus.Entry{
			Data: make(logrus.Fields),
		}
		err := hook.Fire(entry)
		assert.NoError(t, err)
		assert.NotContains(t, entry.Data, "trace_id")
		assert.NotContains(t, entry.Data, "span_id")
	})

	t.Run("no-op when span context is invalid", func(t *testing.T) {
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


func TestFormatValue(t *testing.T) {
	t.Run("string value", func(t *testing.T) {
		result := formatValue("test")
		assert.Equal(t, "test", result)
	})

	t.Run("error value", func(t *testing.T) {
		result := formatValue(assert.AnError)
		assert.Equal(t, assert.AnError.Error(), result)
	})

	t.Run("int value", func(t *testing.T) {
		result := formatValue(42)
		assert.Equal(t, "42", result)
	})

	t.Run("nil value", func(t *testing.T) {
		result := formatValue(nil)
		assert.Equal(t, "<nil>", result)
	})
}

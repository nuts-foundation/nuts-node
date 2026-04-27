/*
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

package oauth

import (
	"context"
	"net/url"

	"go.opentelemetry.io/otel/attribute"
	oteltrace "go.opentelemetry.io/otel/trace"
)

// spanAttributer is implemented by OAuth2 request objects that can expose their non-sensitive
// parameters as OTEL span attributes. Implementors live in the caller's package; the interface
// is matched structurally.
type spanAttributer interface {
	SpanAttributes() []attribute.KeyValue
}

// spanAttributeParams is the allowlist of OAuth2 request parameters extracted from url.Values
// by SetSpanAttributes. Sensitive parameters (credentials, assertions, codes, code_verifiers,
// redirect_uri) are deliberately excluded.
var spanAttributeParams = []string{
	"grant_type",
	"client_id",
	"scope",
	"response_type",
}

// SetSpanAttributes enriches the current OTEL span with non-sensitive OAuth2 request
// parameters so traces and logs can be filtered by them. request may be either a value that
// implements spanAttributer (typically a generated request object that exposes its own
// SpanAttributes method) or a url.Values (used by callers that only have the parameters as
// form/query values, e.g. the authorize endpoint or the outbound token request client).
// No-op if ctx has no valid span or request is neither of those.
func SetSpanAttributes(ctx context.Context, request any) {
	var attrs []attribute.KeyValue
	switch v := request.(type) {
	case spanAttributer:
		attrs = v.SpanAttributes()
	case url.Values:
		for _, name := range spanAttributeParams {
			if value := v.Get(name); value != "" {
				attrs = append(attrs, attribute.String("oauth."+name, value))
			}
		}
	default:
		return
	}
	if len(attrs) == 0 {
		return
	}
	span := oteltrace.SpanFromContext(ctx)
	if !span.SpanContext().IsValid() {
		return
	}
	span.SetAttributes(attrs...)
}

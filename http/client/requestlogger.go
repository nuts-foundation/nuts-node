/*
 * Copyright (C) 2024 Nuts community
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

package client

import (
	"bytes"
	"io"
	"net/http"

	"github.com/nuts-foundation/nuts-node/http/log"
	"github.com/sirupsen/logrus"
)

// These flags control logging of outgoing HTTP requests and responses. They are read at request time
// (not when a client is created), because clients are often created before the HTTP engine configures
// logging: the HTTP engine is configured last, while other engines create their HTTP clients earlier.
var (
	// LogRequests enables logging of outgoing request and response metadata (method, URI, status, headers).
	LogRequests bool
	// LogRequestBodies additionally logs request and response bodies. It has no effect unless LogRequests is set.
	LogRequestBodies bool
)

// maskedHeaders are HTTP headers whose values are replaced with a placeholder when logging,
// to avoid leaking credentials into the logs.
var maskedHeaders = map[string]struct{}{
	"Authorization":       {},
	"Proxy-Authorization": {},
}

const maskedHeaderValue = "[MASKED]"

// loggingTransport logs outgoing HTTP requests and their responses, according to LogRequests and
// LogRequestBodies. It is installed on every client created by this package; whether anything is
// logged is decided per request.
type loggingTransport struct {
	base http.RoundTripper
}

func (l *loggingTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	if !LogRequests {
		return l.base.RoundTrip(request)
	}
	logger := log.Logger()

	logger.WithFields(logrus.Fields{
		"method":  request.Method,
		"uri":     request.URL.String(),
		"headers": maskHeaders(request.Header),
	}).Info("HTTP client request")

	if LogRequestBodies && request.Body != nil && log.IsLoggableContentType(request.Header.Get("Content-Type")) {
		body, err := io.ReadAll(request.Body)
		_ = request.Body.Close()
		if err != nil {
			return nil, err
		}
		request.Body = io.NopCloser(bytes.NewReader(body))
		logger.Infof("HTTP client request body: %s", string(body))
	}

	response, err := l.base.RoundTrip(request)
	if err != nil {
		logger.WithFields(logrus.Fields{
			"method": request.Method,
			"uri":    request.URL.String(),
		}).WithError(err).Info("HTTP client request failed")
		return nil, err
	}

	logger.WithFields(logrus.Fields{
		"method":  request.Method,
		"uri":     request.URL.String(),
		"status":  response.StatusCode,
		"headers": maskHeaders(response.Header),
	}).Info("HTTP client response")

	if LogRequestBodies && response.Body != nil && log.IsLoggableContentType(response.Header.Get("Content-Type")) {
		body, err := io.ReadAll(response.Body)
		_ = response.Body.Close()
		if err != nil {
			return nil, err
		}
		response.Body = io.NopCloser(bytes.NewReader(body))
		logger.Infof("HTTP client response body: %s", string(body))
	}

	return response, nil
}

// maskHeaders returns a copy of the given headers with the values of sensitive headers masked.
func maskHeaders(header http.Header) http.Header {
	masked := make(http.Header, len(header))
	for name, values := range header {
		if _, ok := maskedHeaders[http.CanonicalHeaderKey(name)]; ok {
			masked[name] = []string{maskedHeaderValue}
			continue
		}
		masked[name] = values
	}
	return masked
}

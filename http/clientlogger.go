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

package http

import (
	"bytes"
	"io"
	"net/http"

	"github.com/sirupsen/logrus"
)

// maskedHeaders are HTTP headers whose values are replaced with a placeholder when logging,
// to avoid leaking credentials into the logs.
var maskedHeaders = map[string]struct{}{
	"Authorization":       {},
	"Proxy-Authorization": {},
}

const maskedHeaderValue = "[MASKED]"

// clientRequestLogger is an http.RoundTripper that logs outgoing HTTP requests and their responses.
// Metadata (method, URI, status, headers) is always logged; bodies are logged only when logBody is set.
// Sensitive headers are masked, see maskedHeaders.
type clientRequestLogger struct {
	transport http.RoundTripper
	logger    *logrus.Entry
	logBody   bool
}

func (c *clientRequestLogger) RoundTrip(request *http.Request) (*http.Response, error) {
	c.logger.WithFields(logrus.Fields{
		"method":  request.Method,
		"uri":     request.URL.String(),
		"headers": maskHeaders(request.Header),
	}).Info("HTTP client request")

	if c.logBody && request.Body != nil && isLoggableContentType(request.Header.Get("Content-Type")) {
		body, err := io.ReadAll(request.Body)
		_ = request.Body.Close()
		if err != nil {
			return nil, err
		}
		request.Body = io.NopCloser(bytes.NewReader(body))
		c.logger.Infof("HTTP client request body: %s", string(body))
	}

	response, err := c.transport.RoundTrip(request)
	if err != nil {
		c.logger.WithFields(logrus.Fields{
			"method": request.Method,
			"uri":    request.URL.String(),
		}).WithError(err).Info("HTTP client request failed")
		return nil, err
	}

	c.logger.WithFields(logrus.Fields{
		"method":  request.Method,
		"uri":     request.URL.String(),
		"status":  response.StatusCode,
		"headers": maskHeaders(response.Header),
	}).Info("HTTP client response")

	if c.logBody && response.Body != nil && isLoggableContentType(response.Header.Get("Content-Type")) {
		body, err := io.ReadAll(response.Body)
		_ = response.Body.Close()
		if err != nil {
			return nil, err
		}
		response.Body = io.NopCloser(bytes.NewReader(body))
		c.logger.Infof("HTTP client response body: %s", string(body))
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

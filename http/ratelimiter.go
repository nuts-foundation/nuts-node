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
	"time"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"golang.org/x/time/rate"
)

// internalRateLimiterStore uses a simple TokenBucket for limiting the amount of internal requests.
// It should only be used for internal paths since it does not register the rate limit per caller.
type internalRateLimiterStore struct {
	limiter *rate.Limiter
}

// Allow checks if the amount of calls has not exceeded the limited amount. It ignores the callers' identifier.
func (s *internalRateLimiterStore) Allow(_ string) (bool, error) {
	// no need for locks since this is already managed by the limiter
	return s.limiter.Allow(), nil
}

// newInternalRateLimiterStore creates a new rate limiter store for internal paths
func newInternalRateLimiterStore(interval time.Duration, limitPerInterval rate.Limit, burst int) *internalRateLimiterStore {
	// e.g. limiter for 3000 tx a day with a burst size of 30.
	// This allows a request every 30 seconds: (1/(3000/(3600*24)))
	return &internalRateLimiterStore{
		limiter: rate.NewLimiter(limitPerInterval*rate.Every(interval), burst),
	}
}

// newInternalRateLimiter creates a new internal rate limiter based on the echo middleware RateLimiter.
// It accepts a list of paths which will become limited. Paths are matched against the exact router path, so you can use paths that contain a variable.
// By default, the rateLimiter fails the http request with a http error, but when onlyWarn is set, it allows the request and logs.
func newInternalRateLimiter(protectedPaths map[string][]string, interval time.Duration, limitPerInterval rate.Limit, burst int) echo.MiddlewareFunc {
	return middleware.RateLimiterWithConfig(middleware.RateLimiterConfig{
		// Returning true means skipping the middleware
		Skipper: func(c echo.Context) bool {
			for _, path := range protectedPaths[c.Request().Method] {
				if c.Path() == path {
					return false
				}
			}

			return true
		},
		IdentifierExtractor: func(ctx echo.Context) (string, error) {
			return "", nil // we use the limiter only for internal calls, so no identifier such as an IP is used
		},
		ErrorHandler: func(context echo.Context, err error) error {
			return &echo.HTTPError{
				Code:     middleware.ErrExtractorError.Code,
				Message:  middleware.ErrExtractorError.Message,
				Internal: err,
			}
		},
		DenyHandler: func(context echo.Context, identifier string, err error) error {
			return &echo.HTTPError{
				Code:     middleware.ErrRateLimitExceeded.Code,
				Message:  middleware.ErrRateLimitExceeded.Message,
				Internal: err,
			}
		},
		// use a store for max 3000 calls a day with a burst rate of 30
		Store: newInternalRateLimiterStore(interval, limitPerInterval, burst),
	})
}

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

package cache

import (
	"fmt"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"time"
)

// Middleware is a middleware that sets the Cache-Control header (no-cache or max-age) for the given request URLs.
// Use MaxAge or NoCache to create a new instance.
type Middleware struct {
	Skipper middleware.Skipper
	maxAge  time.Duration
}

func (m Middleware) Handle(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		if !m.Skipper(c) {
			if m.maxAge == -1 {
				c.Response().Header().Set("Cache-Control", "no-cache")
				// Pragma is deprecated (HTTP/1.0) but it's specified by OAuth2 RFC6749,
				// so specify it for compliance.
				c.Response().Header().Set("Pragma", "no-store")
			} else if m.maxAge > 0 {
				c.Response().Header().Set("Cache-Control", fmt.Sprintf("max-age=%d", int(m.maxAge.Seconds())))
			}
		}
		return next(c)
	}
}

// MaxAge creates a new middleware that sets the Cache-Control header to the given max-age for the given request URLs.
func MaxAge(maxAge time.Duration, requestURLs ...string) Middleware {
	return Middleware{
		Skipper: matchRequestPathSkipper(requestURLs),
		maxAge:  maxAge,
	}
}

// NoCache creates a new middleware that sets the Cache-Control header to no-cache for the given request URLs.
func NoCache(requestURLs ...string) Middleware {
	return Middleware{
		Skipper: matchRequestPathSkipper(requestURLs),
		maxAge:  -1,
	}
}

func matchRequestPathSkipper(requestURLs []string) func(c echo.Context) bool {
	return func(c echo.Context) bool {
		for _, curr := range requestURLs {
			if c.Path() == curr {
				return false
			}
		}
		return true
	}
}

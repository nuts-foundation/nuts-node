package cache

import (
	"fmt"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"strings"
	"time"
)

type Middleware struct {
	Skipper middleware.Skipper
	maxAge  time.Duration
}

func (m Middleware) Handle(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		if !m.Skipper(c) {
			if m.maxAge > 0 {
				c.Response().Header().Set("Cache-Control", fmt.Sprintf("max-age=%d", int(m.maxAge.Seconds())))
			}
		}
		return next(c)
	}
}

// MaxAge creates a new middleware that sets the Cache-Control header to the given max-age for the given request URLs.
func MaxAge(maxAge time.Duration, requestURLs []string) Middleware {
	return Middleware{
		Skipper: func(c echo.Context) bool {
			for _, curr := range requestURLs {
				// trim leading and trailing /before comparing, just in case
				if strings.Trim(c.Request().URL.Path, "/") == strings.Trim(curr, "/") {
					return false
				}
			}
			return true
		},
		maxAge: maxAge,
	}
}

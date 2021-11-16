package http

import (
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestNewInternalRateLimiter(t *testing.T) {
	t.Run("it works", func(t *testing.T) {
		e := echo.New()
		rlMiddleware := newInternalRateLimiter(map[string][]string{http.MethodPost: {"/foo"}}, time.Minute, 30, 2)

		handler := func(c echo.Context) error {
			return c.String(http.StatusOK, "test")
		}

		testcases := []struct {
			method            string
			expectedStatus    int
			waitBeforeRequest time.Duration
			path              string
		}{
			{http.MethodPost, http.StatusOK, 0, "/foo"},               // first request in burst
			{http.MethodPost, http.StatusOK, 0, "/foo"},               // second request in burst
			{http.MethodPost, http.StatusTooManyRequests, 0, "/foo"},  // bucket empty
			{http.MethodPost, http.StatusOK, 0, "/other"},             // unprotected path should still work
			{http.MethodGet, http.StatusOK, 0, "/foo"},                // other method same path should still work
			{http.MethodPost, http.StatusTooManyRequests, 0, "/foo"},  // check bucket still empty
			{http.MethodPost, http.StatusOK, 2 * time.Second, "/foo"}, // wait 2 seconds to refill bucket
			{http.MethodPost, http.StatusTooManyRequests, 0, "/foo"},  // bucket empty again
		}

		for _, testcase := range testcases {
			time.Sleep(testcase.waitBeforeRequest)
			req := httptest.NewRequest(testcase.method, testcase.path, nil)
			rec := httptest.NewRecorder()
			c := e.NewContext(req, rec)
			c.SetPath(testcase.path)
			_ = rlMiddleware(handler)(c)
			assert.Equalf(t, testcase.expectedStatus, rec.Code, "unexpected HTTP response for %s on %s", testcase.method, testcase.path)
		}
	})

}

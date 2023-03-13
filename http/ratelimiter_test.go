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
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
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

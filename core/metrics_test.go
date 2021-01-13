/*
 * Nuts go core
 * Copyright (C) 2020 Nuts community
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
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
)

func TestNewMetricsEngine(t *testing.T) {
	mEngine := NewMetricsEngine()
	_ = mEngine.Configure()
	e := echo.New()
	mEngine.Routes(e)

	t.Run("Metrics endpoint returns information about current process", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
		rec := httptest.NewRecorder()
		e.ServeHTTP(rec, req)
		defer rec.Result().Body.Close()

		bodyBytes, _ := ioutil.ReadAll(rec.Result().Body)

		fmt.Println(string(bodyBytes))

		bodyString := string(bodyBytes)

		assert.True(t, strings.Contains(bodyString, "go_goroutines"))
		assert.True(t, strings.Contains(bodyString, "go_memstats"))
		assert.True(t, strings.Contains(bodyString, "go_threads"))
		assert.True(t, strings.Contains(bodyString, "promhttp_metric_handler_requests_in_flight"))
	})

	t.Run("calling configure twice is ok", func(t *testing.T) {
		err := mEngine.Configure()

		assert.NoError(t, err)
	})
}

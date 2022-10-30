/*
 * Copyright (C) 2021 Nuts community
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

package status

import (
	"context"
	"github.com/golang/mock/gomock"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/mock"
	"github.com/nuts-foundation/nuts-node/test"
	"github.com/stretchr/testify/assert"
	"net/http"
	"testing"
)

func TestNewStatusEngine_Routes(t *testing.T) {
	t.Run("Registers a single route for listing all engines", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		echo := core.NewMockEchoRouter(ctrl)

		echo.EXPECT().Add(http.MethodGet, "/status/diagnostics", gomock.Any())
		echo.EXPECT().Add(http.MethodGet, "/status", gomock.Any())
		echo.EXPECT().Add(http.MethodGet, "/health", gomock.Any())

		NewStatusEngine(core.NewSystem()).(*status).Routes(echo)
	})
}

func TestNewStatusEngine_Diagnostics(t *testing.T) {
	system := core.NewSystem()
	system.RegisterEngine(NewStatusEngine(system))
	system.RegisterEngine(core.NewMetricsEngine())

	t.Run("diagnostics() returns core info", func(t *testing.T) {
		system := NewStatusEngine(system)
		ds := system.(*status).Diagnostics()
		assert.Len(t, ds, 4)
		idx := 0
		// Uptime
		assert.Equal(t, "uptime", ds[idx].Name())
		assert.NotEmpty(t, ds[idx].String())
		// SoftwareVersion
		idx++
		assert.Equal(t, "software_version", ds[idx].Name())
		assert.Equal(t, core.Version(), ds[idx].String())
		// Commit
		idx++
		assert.Equal(t, "git_commit", ds[idx].Name())
		assert.Equal(t, "0", ds[idx].String())
		// Os/Arg
		idx++
		assert.Equal(t, "os_arch", ds[idx].Name())
		assert.Equal(t, core.OSArch(), ds[idx].String())
	})

	t.Run("diagnosticsOverview() YAML output", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		echo := mock.NewMockContext(ctrl)
		echo.EXPECT().Request().Return(&http.Request{Header: map[string][]string{}})

		expected :=
			`status:
    git_commit: "0"`
		echo.EXPECT().String(http.StatusOK, test.Contains(expected))

		(&status{system: system}).diagnosticsOverview(echo)
	})
	t.Run("diagnosticsOverview() JSON output", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		echo := mock.NewMockContext(ctrl)
		echo.EXPECT().Request().Return(&http.Request{Header: map[string][]string{"Accept": {"application/json"}}})

		echo.EXPECT().JSON(http.StatusOK, gomock.Any())

		(&status{system: system}).diagnosticsOverview(echo)
	})
}

func TestStatusOK(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	echo := mock.NewMockContext(ctrl)

	echo.EXPECT().String(http.StatusOK, "OK")

	statusOK(echo)
}

func Test_status_healthChecks(t *testing.T) {
	t.Run("status UP", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		echoContext := mock.NewMockContext(ctrl)
		echoContext.EXPECT().Request().Return(&http.Request{})
		echoContext.EXPECT().JSON(200, core.HealthCheckResult{
			Status:  core.HealthStatusUp,
			Details: make(map[string]core.HealthCheckResult),
		})
		s := status{system: core.NewSystem()}

		err := s.checkHealth(echoContext)

		assert.NoError(t, err)
	})
	t.Run("status DOWN", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		echoContext := mock.NewMockContext(ctrl)
		echoContext.EXPECT().Request().Return(&http.Request{})
		echoContext.EXPECT().JSON(503, gomock.Any())
		system := core.NewSystem()
		system.RegisterEngine(&healthCheckingEngine{
			name: "engine1",
			check: func(_ context.Context) map[string]core.HealthCheckResult {
				return map[string]core.HealthCheckResult{
					"check1": {
						Status: core.HealthStatusDown,
					},
				}
			},
		})
		s := status{system: system}

		err := s.checkHealth(echoContext)

		assert.NoError(t, err)
	})
}

func Test_status_doHealthChecks(t *testing.T) {
	t.Run("no engines", func(t *testing.T) {
		s := status{system: core.NewSystem()}

		result := s.doCheckHealth(context.Background())

		assert.Equal(t, core.HealthStatusUp, result.Status)
		assert.Empty(t, result.Details)
	})
	t.Run("time-out", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		system := core.NewSystem()
		system.RegisterEngine(&healthCheckingEngine{
			name: "engine1",
			check: func(ctx context.Context) map[string]core.HealthCheckResult {
				cancel() // causes health checking to quit
				return map[string]core.HealthCheckResult{
					"check1": {
						Status:  core.HealthStatusUp,
						Details: "all is fine",
					},
				}
			},
		})
		system.RegisterEngine(&healthCheckingEngine{
			name: "engine2",
			check: func(_ context.Context) map[string]core.HealthCheckResult {
				return map[string]core.HealthCheckResult{
					"check2": {
						Status:  core.HealthStatusUp,
						Details: "all is fine",
					},
				}
			},
		})
		s := status{system: system}

		result := s.doCheckHealth(ctx)

		assert.Equal(t, core.HealthStatusUnknown, result.Status)
		// Due to time-out before checking engine2, only the check results of engine1 should be there,
		// and a result of the healthcheck indicating the time-out.
		checks := result.Details.(map[string]core.HealthCheckResult)
		assert.Len(t, checks, 2)
		assert.Contains(t, checks, "engine1.check1")
		assert.NotContains(t, checks, "engine2.check2")
		assert.Contains(t, checks, "healthcheck")
		assert.Equal(t, core.HealthStatusUnknown, checks["healthcheck"].Status)
		assert.Equal(t, "health check aborted due to time-out", checks["healthcheck"].Details)
	})
	t.Run("overall status DOWN", func(t *testing.T) {
		system := core.NewSystem()
		system.RegisterEngine(&healthCheckingEngine{
			name: "engine1",
			check: func(_ context.Context) map[string]core.HealthCheckResult {
				return map[string]core.HealthCheckResult{
					"check1": {
						Status: core.HealthStatusUp,
					},
					"check2": {
						Status: core.HealthStatusUnknown,
					},
					"check3": {
						Status: core.HealthStatusDown,
					},
				}
			},
		})
		s := status{system: system}

		result := s.doCheckHealth(context.Background())

		assert.Equal(t, core.HealthStatusDown, result.Status)
	})
	t.Run("overall status UNKNOWN", func(t *testing.T) {
		system := core.NewSystem()
		system.RegisterEngine(&healthCheckingEngine{
			name: "engine1",
			check: func(_ context.Context) map[string]core.HealthCheckResult {
				return map[string]core.HealthCheckResult{
					"check1": {
						Status: core.HealthStatusUp,
					},
					"check2": {
						Status: core.HealthStatusUnknown,
					},
				}
			},
		})
		s := status{system: system}

		result := s.doCheckHealth(context.Background())

		assert.Equal(t, core.HealthStatusUnknown, result.Status)
	})
}

type healthCheckingEngine struct {
	name  string
	check func(ctx context.Context) map[string]core.HealthCheckResult
}

func (h healthCheckingEngine) CheckHealth(ctx context.Context) map[string]core.HealthCheckResult {
	return h.check(ctx)
}

func (h healthCheckingEngine) Name() string {
	return h.name
}

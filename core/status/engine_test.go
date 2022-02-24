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
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/test"
	"net/http"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/nuts-foundation/nuts-node/mock"
	"github.com/stretchr/testify/assert"
)

func TestNewStatusEngine_Routes(t *testing.T) {
	t.Run("Registers a single route for listing all engines", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		echo := core.NewMockEchoRouter(ctrl)

		echo.EXPECT().Add(http.MethodGet, "/status/diagnostics", gomock.Any())
		echo.EXPECT().Add(http.MethodGet, "/status", gomock.Any())

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

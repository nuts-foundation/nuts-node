/*
 * Copyright (C) 2023 Nuts community
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

package audit

import (
	"net/http"
	"testing"

	"github.com/labstack/echo/v4"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/stretchr/testify/assert"
)

func TestMiddleware(t *testing.T) {
	req := http.Request{RemoteAddr: "1.2.3.4:1234"}
	server := echo.New()
	server.IPExtractor = echo.ExtractIPDirect()
	t.Run("with auth", func(t *testing.T) {
		ctx := server.NewContext(&req, nil)
		ctx.Set(core.UserContextKey, "user")

		SetOnEchoContext(ctx, "mod", "op")

		actual := InfoFromContext(ctx.Request().Context())
		assert.Equal(t, "mod.op", actual.Operation)
		assert.Equal(t, "user@1.2.3.4", actual.Actor)
	})
	t.Run("without auth", func(t *testing.T) {
		ctx := server.NewContext(&req, nil)

		SetOnEchoContext(ctx, "mod", "op")

		actual := InfoFromContext(ctx.Request().Context())
		assert.Equal(t, "mod.op", actual.Operation)
		assert.Equal(t, "1.2.3.4", actual.Actor)
	})
}

func TestStrictMiddleware(t *testing.T) {
	ctx := echo.New().NewContext(&http.Request{}, nil)
	ctx.Set(core.UserContextKey, "user")

	StrictMiddleware(func(ctx echo.Context, _ interface{}) (interface{}, error) {
		return nil, nil
	}, "mod", "op")(ctx, nil)

	AssertAuditInfo(t, ctx, "user@", "mod", "op")
}

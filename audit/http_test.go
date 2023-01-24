package audit

import (
	"github.com/labstack/echo/v4"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/stretchr/testify/assert"
	"net/http"
	"testing"
)

func TestMiddleware(t *testing.T) {
	req := http.Request{RemoteAddr: "1.2.3.4:1234"}
	server := echo.New()
	server.IPExtractor = echo.ExtractIPDirect()
	t.Run("with auth", func(t *testing.T) {
		ctx := server.NewContext(&req, nil)
		ctx.Set(core.UserContextKey, "user")

		Middleware(ctx, "mod", "op")

		actual := InfoFromContext(ctx.Request().Context())
		assert.Equal(t, "mod.op", actual.Operation)
		assert.Equal(t, "user@1.2.3.4", actual.Actor)
	})
	t.Run("without auth", func(t *testing.T) {
		ctx := server.NewContext(&req, nil)

		Middleware(ctx, "mod", "op")

		actual := InfoFromContext(ctx.Request().Context())
		assert.Equal(t, "mod.op", actual.Operation)
		assert.Equal(t, "1.2.3.4", actual.Actor)
	})
}

func TestStrictMiddleware(t *testing.T) {
	type args struct {
		next        func(ctx echo.Context, args interface{}) (interface{}, error)
		moduleName  string
		operationID string
	}
	tests := []struct {
		name string
		args args
		want func(ctx echo.Context, args interface{}) (interface{}, error)
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equalf(t, tt.want, StrictMiddleware(tt.args.next, tt.args.moduleName, tt.args.operationID), "StrictMiddleware(%v, %v, %v)", tt.args.next, tt.args.moduleName, tt.args.operationID)
		})
	}
}

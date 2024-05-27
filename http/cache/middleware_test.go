package cache

import (
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/require"
	"net/http/httptest"
	"testing"
	"time"
)

func TestMaxAge(t *testing.T) {
	t.Run("match", func(t *testing.T) {
		e := echo.New()
		httpResponse := httptest.NewRecorder()
		echoContext := e.NewContext(httptest.NewRequest("GET", "/a/", nil), httpResponse)

		err := MaxAge(time.Minute, []string{"a", "b"}).Handle(func(c echo.Context) error {
			return c.String(200, "OK")
		})(echoContext)

		require.NoError(t, err)
		require.Equal(t, "max-age=60", httpResponse.Header().Get("Cache-Control"))
	})
	t.Run("no match", func(t *testing.T) {
		e := echo.New()
		httpResponse := httptest.NewRecorder()
		echoContext := e.NewContext(httptest.NewRequest("GET", "/c", nil), httpResponse)

		err := MaxAge(time.Minute, []string{"a", "b"}).Handle(func(c echo.Context) error {
			return c.String(200, "OK")
		})(echoContext)

		require.NoError(t, err)
		require.Empty(t, httpResponse.Header().Get("Cache-Control"))
	})

}

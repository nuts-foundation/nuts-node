package core

import (
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
		echo := NewMockEchoRouter(ctrl)

		echo.EXPECT().Add(http.MethodGet, "/status/diagnostics", gomock.Any())
		echo.EXPECT().Add(http.MethodGet, "/status", gomock.Any())

		NewStatusEngine(NewSystem()).(*status).Routes(echo)
	})
}

func TestNewStatusEngine_Diagnostics(t *testing.T) {
	system := NewSystem()
	system.RegisterEngine(NewStatusEngine(system))
	system.RegisterEngine(NewMetricsEngine())

	t.Run("diagnostics() returns engine list", func(t *testing.T) {
		ds := NewStatusEngine(system).(*status).Diagnostics()
		assert.Len(t, ds, 1)
		assert.Equal(t, "Registered engines", ds[0].Name())
		assert.Equal(t, "Status,Metrics", ds[0].String())
	})

	t.Run("diagnosticsOverview() renders text output of diagnostics", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		echo := mock.NewMockContext(ctrl)

		echo.EXPECT().String(http.StatusOK, "Status\n\tRegistered engines: Status,Metrics")

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

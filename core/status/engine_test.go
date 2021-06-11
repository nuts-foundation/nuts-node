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

	t.Run("diagnostics() returns engine list", func(t *testing.T) {
		system := NewStatusEngine(system)
		ds := system.(*status).Diagnostics()
		assert.Len(t, ds, 5)
		// Registered engines
		assert.Equal(t, "Registered engines", ds[0].Name())
		assert.Equal(t, "Status,Metrics", ds[0].String())
		// Uptime
		assert.Equal(t, "Uptime", ds[1].Name())
		assert.NotEmpty(t, ds[1].String())
		// SoftwareVersion
		assert.Equal(t, "SoftwareVersion", ds[2].Name())
		assert.Equal(t, core.Version(), ds[2].String())
		// Commit
		assert.Equal(t, "Git commit", ds[3].Name())
		assert.Equal(t, "0", ds[3].String())
		// Os/Arg
		assert.Equal(t, "OS/Arch", ds[4].Name())
		assert.Equal(t, core.OSArch(), ds[4].String())
	})

	t.Run("diagnosticsOverview() renders text output of diagnostics", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		echo := mock.NewMockContext(ctrl)

		echo.EXPECT().String(http.StatusOK, test.Contains("Registered engines: Status,Metrics"))

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

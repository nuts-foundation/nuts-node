package storage

import (
	"fmt"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestAzureSQLIntegration(t *testing.T) {
	t.Log("This integration test requires a connection to an Azure SQL Server.")
	t.Skip()
	var server = "<server>.database.windows.net"
	var port = 1433
	var db = "<db>"

	instance := New().(*engine)
	instance.config = DefaultConfig()
	instance.config.SQL.ConnectionString = fmt.Sprintf("azuresql://server=%s;port=%d;database=%s;fedauth=ActiveDirectoryDefault;", server, port, db)
	println("Connecting...")
	err := instance.Configure(core.TestServerConfig())
	println("Successfully connected to Azure SQL Server!")
	require.NoError(t, err)
	defer func() {
		_ = instance.Shutdown()
	}()
	err = instance.Start()
	require.NoError(t, err)
}

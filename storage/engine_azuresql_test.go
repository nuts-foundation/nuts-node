/*
 * Copyright (C) 2024 Nuts community
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

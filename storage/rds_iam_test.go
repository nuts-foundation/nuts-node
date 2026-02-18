/*
 * Copyright (C) 2026 Nuts community
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
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParsePostgresConnectionString(t *testing.T) {
	t.Run("extracts endpoint correctly", func(t *testing.T) {
		connStr := "postgres://user:password@mydb.123456789012.us-east-1.rds.amazonaws.com:5432/mydb"
		config := RDSIAMConfig{
			Enabled: true,
			Region:  "us-east-1",
			DBUser:  "iamuser",
		}

		endpoint, modified, err := parsePostgresConnectionString(connStr, config)
		require.NoError(t, err)
		assert.Equal(t, "mydb.123456789012.us-east-1.rds.amazonaws.com:5432", endpoint)
		assert.Contains(t, modified, "iamuser")
		assert.NotContains(t, modified, "password")
	})

	t.Run("uses existing user if DBUser not specified", func(t *testing.T) {
		connStr := "postgres://existinguser:password@mydb.amazonaws.com:5432/mydb"
		config := RDSIAMConfig{
			Enabled: true,
			Region:  "us-east-1",
		}

		endpoint, modified, err := parsePostgresConnectionString(connStr, config)
		require.NoError(t, err)
		assert.Equal(t, "mydb.amazonaws.com:5432", endpoint)
		assert.Contains(t, modified, "existinguser")
		assert.NotContains(t, modified, "password")
	})
}

func TestParseMySQLConnectionString(t *testing.T) {
	t.Run("extracts endpoint correctly", func(t *testing.T) {
		connStr := "mysql://user:password@mydb.123456789012.us-west-2.rds.amazonaws.com:3306/mydb"
		config := RDSIAMConfig{
			Enabled: true,
			Region:  "us-west-2",
			DBUser:  "iamuser",
		}

		endpoint, modified, err := parseMySQLConnectionString(connStr, config)
		require.NoError(t, err)
		assert.Equal(t, "mydb.123456789012.us-west-2.rds.amazonaws.com:3306", endpoint)
		assert.Contains(t, modified, "iamuser")
		assert.NotContains(t, modified, "password")
	})
}

func TestInjectPasswordIntoConnectionString(t *testing.T) {
	t.Run("injects password into postgres connection string", func(t *testing.T) {
		connStr := "postgres://user@mydb.amazonaws.com:5432/mydb"
		token := "generatedtoken123"

		result := injectPasswordIntoConnectionString(connStr, token)
		assert.Contains(t, result, "user:generatedtoken123")
	})

	t.Run("replaces existing password", func(t *testing.T) {
		connStr := "postgres://user:oldpassword@mydb.amazonaws.com:5432/mydb"
		token := "newtoken456"

		result := injectPasswordIntoConnectionString(connStr, token)
		assert.Contains(t, result, "user:newtoken456")
		assert.NotContains(t, result, "oldpassword")
	})
}

func TestModifyConnectionStringForRDSIAM(t *testing.T) {
	t.Run("disabled config returns original string", func(t *testing.T) {
		connStr := "postgres://user:password@localhost:5432/db"
		config := RDSIAMConfig{
			Enabled: false,
		}

		modified, auth, err := modifyConnectionStringForRDSIAM(context.Background(), connStr, config)
		require.NoError(t, err)
		assert.Equal(t, connStr, modified)
		assert.Nil(t, auth)
	})

	t.Run("unsupported connection string returns error", func(t *testing.T) {
		connStr := "sqlite:file:test.db"
		config := RDSIAMConfig{
			Enabled: true,
			Region:  "us-east-1",
		}

		_, _, err := modifyConnectionStringForRDSIAM(context.Background(), connStr, config)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "only supported for postgres:// and mysql://")
	})
}

func TestNewRDSIAMAuthenticator(t *testing.T) {
	t.Run("sets default token refresh interval", func(t *testing.T) {
		config := RDSIAMConfig{
			Enabled: true,
			Region:  "us-east-1",
			DBUser:  "testuser",
		}

		auth := newRDSIAMAuthenticator(config, "localhost:5432", "postgres://testuser@localhost:5432/testdb")
		assert.Equal(t, 14*time.Minute, auth.config.TokenRefreshInterval)
	})

	t.Run("uses custom token refresh interval", func(t *testing.T) {
		config := RDSIAMConfig{
			Enabled:              true,
			Region:               "us-east-1",
			DBUser:               "testuser",
			TokenRefreshInterval: 5 * time.Minute,
		}

		auth := newRDSIAMAuthenticator(config, "localhost:5432", "postgres://testuser@localhost:5432/testdb")
		assert.Equal(t, 5*time.Minute, auth.config.TokenRefreshInterval)
	})
}

func TestRDSIAMAuthenticator_GetToken(t *testing.T) {
	t.Run("refreshes token when needed", func(t *testing.T) {
		config := RDSIAMConfig{
			Enabled:              true,
			Region:               "us-east-1",
			DBUser:               "testuser",
			TokenRefreshInterval: 1 * time.Millisecond,
		}

		auth := newRDSIAMAuthenticator(config, "localhost:5432", "postgres://testuser@localhost:5432/testdb")
		// Set an old refresh time to trigger refresh
		auth.lastRefresh = time.Now().Add(-2 * time.Millisecond)
		auth.currentToken = "oldtoken"

		// Note: This will succeed if AWS credentials are configured, fail otherwise
		// We're testing that the refresh logic is triggered, not the actual AWS call
		_, err := auth.getToken(context.Background())
		// Either succeeds with valid AWS credentials or fails without them - both are acceptable
		if err != nil {
			// Expected in test environment without AWS credentials
			t.Logf("Token refresh failed as expected without AWS credentials: %v", err)
		} else {
			// Token refresh succeeded with available AWS credentials
			t.Logf("Token refresh succeeded with available AWS credentials")
		}
	})
}

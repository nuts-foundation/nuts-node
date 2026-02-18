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
	"strings"
	"testing"

	"github.com/knadh/koanf/providers/env"
	"github.com/knadh/koanf/v2"
	"github.com/stretchr/testify/assert"
)

func TestRDSIAMConfig_EnvironmentVariables(t *testing.T) {
	t.Run("environment variables with dots notation", func(t *testing.T) {
		// Set environment variables using the NUTS_ prefix with underscores
		// These should map to dot notation in the config
		t.Setenv("NUTS_STORAGE_SQL_RDSIAM_ENABLED", "true")
		t.Setenv("NUTS_STORAGE_SQL_RDSIAM_REGION", "us-east-1")
		t.Setenv("NUTS_STORAGE_SQL_RDSIAM_DBUSER", "test-user")

		// Load config using the same pattern as core/config.go
		configMap := koanf.New(".")
		e := env.ProviderWithValue("NUTS_", ".", func(rawKey string, rawValue string) (string, interface{}) {
			key := strings.Replace(strings.ToLower(strings.TrimPrefix(rawKey, "NUTS_")), "_", ".", -1)
			return key, rawValue
		})
		err := configMap.Load(e, nil)
		assert.NoError(t, err)

		// Debug: print all keys
		t.Logf("Keys in configMap: %v", configMap.Keys())

		// Verify the raw keys are correct
		assert.Equal(t, true, configMap.Bool("storage.sql.rdsiam.enabled"))
		assert.Equal(t, "us-east-1", configMap.String("storage.sql.rdsiam.region"))
		assert.Equal(t, "test-user", configMap.String("storage.sql.rdsiam.dbuser"))

		// Unmarshal into config struct
		var config Config
		err = configMap.UnmarshalWithConf("storage", &config, koanf.UnmarshalConf{
			FlatPaths: false,
		})
		assert.NoError(t, err)

		// Verify the values are correctly loaded
		assert.True(t, config.SQL.RDSIAM.Enabled)
		assert.Equal(t, "us-east-1", config.SQL.RDSIAM.Region)
		assert.Equal(t, "test-user", config.SQL.RDSIAM.DBUser)
	})

	t.Run("environment variables should map to correct config keys", func(t *testing.T) {
		// This test verifies that the koanf tags in the structs are correct
		// and that environment variables map properly to the config structure
		t.Setenv("NUTS_STORAGE_SQL_CONNECTION", "postgres://user@host:5432/db")
		t.Setenv("NUTS_STORAGE_SQL_RDSIAM_ENABLED", "true")
		t.Setenv("NUTS_STORAGE_SQL_RDSIAM_REGION", "eu-west-1")
		t.Setenv("NUTS_STORAGE_SQL_RDSIAM_DBUSER", "nuts-node")

		configMap := koanf.New(".")
		e := env.ProviderWithValue("NUTS_", ".", func(rawKey string, rawValue string) (string, interface{}) {
			key := strings.Replace(strings.ToLower(strings.TrimPrefix(rawKey, "NUTS_")), "_", ".", -1)
			return key, rawValue
		})
		err := configMap.Load(e, nil)
		assert.NoError(t, err)

		var config Config
		err = configMap.UnmarshalWithConf("storage", &config, koanf.UnmarshalConf{
			FlatPaths: false,
		})
		assert.NoError(t, err)

		assert.Equal(t, "postgres://user@host:5432/db", config.SQL.ConnectionString)
		assert.True(t, config.SQL.RDSIAM.Enabled)
		assert.Equal(t, "eu-west-1", config.SQL.RDSIAM.Region)
		assert.Equal(t, "nuts-node", config.SQL.RDSIAM.DBUser)
	})
}

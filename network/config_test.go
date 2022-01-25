/*
 * Copyright (C) 2022 Nuts community
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

package network

import (
	"github.com/nuts-foundation/nuts-node/core"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDefaultConfig(t *testing.T) {
	defs := DefaultConfig()
	assert.True(t, defs.EnableTLS)
	assert.Equal(t, ":5555", defs.GrpcAddr)
}

func TestConfig_loadTrustStore(t *testing.T) {
	t.Run("configured", func(t *testing.T) {
		cfg := DefaultConfig()
		cfg.TrustStoreFile = "test/truststore.pem"
		store, err := core.LoadTrustStore(cfg.TrustStoreFile)
		assert.NoError(t, err)
		assert.NotNil(t, store)
	})
	t.Run("invalid PEM file", func(t *testing.T) {
		cfg := DefaultConfig()
		cfg.TrustStoreFile = "config_test.go"
		store, err := core.LoadTrustStore(cfg.TrustStoreFile)
		assert.Error(t, err)
		assert.Nil(t, store)
	})
	t.Run("not configured", func(t *testing.T) {
		cfg := DefaultConfig()
		cfg.TrustStoreFile = ""
		store, err := core.LoadTrustStore(cfg.TrustStoreFile)
		assert.Error(t, err)
		assert.Nil(t, store)
	})
}

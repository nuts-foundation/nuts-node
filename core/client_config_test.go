/*
 * Nuts node
 * Copyright (C) 2021 Nuts community
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

package core

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_GetAddress(t *testing.T) {
	t.Run("address has http prefix", func(t *testing.T) {
		os.Setenv("NUTS_ADDRESS", "https://localhost")
		defer os.Unsetenv("NUTS_ADDRESS")
		cfg := NewClientConfig()
		err := cfg.Load()
		assert.NoError(t, err)
		assert.Equal(t, "https://localhost", cfg.GetAddress())
	})
	t.Run("address has no http prefix", func(t *testing.T) {
		os.Setenv("NUTS_ADDRESS", "localhost")
		defer os.Unsetenv("NUTS_ADDRESS")
		cfg := NewClientConfig()
		err := cfg.Load()
		assert.NoError(t, err)
		assert.Equal(t, "http://localhost", cfg.GetAddress())
	})
}

func TestClientConfigFlags(t *testing.T) {
	os.Args = []string{"nuts", "--" + addressFlag + "=localhost:1111", "--" + clientTimeoutFlag + "=20ms"}
	flags := ClientConfigFlags()
	address, err := flags.GetString(addressFlag)
	assert.NoError(t, err)
	duration, err := flags.GetDuration(clientTimeoutFlag)
	assert.NoError(t, err)
	assert.Equal(t, "localhost:1111", address)
	assert.Equal(t, "20ms", duration.String())
}

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
package engine

import (
	"testing"

	"github.com/stretchr/testify/assert"

	core "github.com/nuts-foundation/nuts-node/core"
)

func TestSearchOrg(t *testing.T) {
	// Register test instance singleton
}

func TestPrintVersion(t *testing.T) {
	// Register test instance singleton
	command := cmd()
	command.SetArgs([]string{"version"})
	err := command.Execute()
	assert.NoError(t, err)
}

func Test_flagSet(t *testing.T) {
	assert.NotNil(t, flagSet())
}

func TestNewRegistryEngine(t *testing.T) {
	// Register test instance singleton
	t.Run("instance", func(t *testing.T) {
		assert.NotNil(t, NewRegistryEngine())
	})

	t.Run("configuration", func(t *testing.T) {
		e := NewRegistryEngine()
		cfg := core.NutsConfig()
		cfg.RegisterFlags(e.Cmd, e)
		assert.NoError(t, cfg.InjectIntoEngine(e))
	})
}

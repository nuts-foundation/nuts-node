/*
 * Copyright (C) 2023 Nuts community
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

package pki

import (
	"context"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/stretchr/testify/assert"
	"testing"
)

func Test_New(t *testing.T) {
	e := New()

	assert.IsType(t, &PKI{}, e)
	assert.Equal(t, DefaultConfig(), e.config)
	assert.Nil(t, e.validator)
}

func TestPKI_Name(t *testing.T) {
	e := New()
	assert.Equal(t, "PKI", e.Name())
}

func TestPKI_Config(t *testing.T) {
	e := New()

	cfgPtr := e.Config()

	assert.Same(t, &e.config, cfgPtr)
	assert.IsType(t, Config{}, e.config)
}

func TestPKI_Configure(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		e := New()

		err := e.Configure(core.ServerConfig{})

		assert.NoError(t, err)
		assert.NotNil(t, e.validator)
	})
	t.Run("invalid config", func(t *testing.T) {
		e := New()
		e.config.Denylist = DenylistConfig{
			URL:           "example.com",
			TrustedSigner: "definitely not valid",
		}

		err := e.Configure(core.ServerConfig{})

		assert.Error(t, err)
	})
}

func TestPKI_Runnable(t *testing.T) {
	e := New()
	e.validator = &validator{}

	assert.Nil(t, e.ctx)
	assert.Nil(t, e.shutdown)

	err := e.Start()
	defer e.shutdown() // prevent go routine leak in the validator

	assert.NoError(t, err)
	assert.NotNil(t, e.ctx)
	assert.NotNil(t, e.shutdown)

	err = e.Shutdown()

	assert.NoError(t, err)
	assert.ErrorIs(t, e.ctx.Err(), context.Canceled)
}

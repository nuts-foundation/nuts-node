/*
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

package cmd

import (
	"github.com/nuts-foundation/nuts-node/auth"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/stretchr/testify/require"
	"sort"
	"testing"

	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
)

func TestFlagSet(t *testing.T) {
	flags := FlagSet()

	var keys []string

	// Assert all start with module config key
	flags.VisitAll(func(flag *pflag.Flag) {
		keys = append(keys, flag.Name)
	})

	sort.Strings(keys)

	assert.Equal(t, []string{
		ConfAccessTokenLifeSpan,
		ConfAuthEndpointEnabled,
		ConfClockSkew,
		ConfContractValidators,
		ConfHTTPTimeout,
		ConfAutoUpdateIrmaSchemas,
		ConfIrmaCorsOrigin,
		ConfIrmaSchemeManager,
	}, keys)
}

func TestIrmaConfigInjection(t *testing.T) {
	serverCfg := core.NewServerConfig()
	serverCfg.Verbosity = "debug"
	t.Setenv("NUTS_AUTH_IRMA_SCHEMEMANAGER", "irma-demo")
	t.Setenv("NUTS_AUTH_IRMA_AUTOUPDATESCHEMES", "true")
	err := serverCfg.Load(FlagSet())
	require.NoError(t, err)
	system := core.System{Config: serverCfg}
	engine := auth.Auth{}

	err = system.Config.InjectIntoEngine(&engine)
	require.NoError(t, err)

	cfg := engine.Config().(*auth.Config)
	assert.Equal(t, "irma-demo", cfg.Irma.SchemeManager)
	assert.True(t, cfg.Irma.AutoUpdateSchemas)
}

/*
 * Nuts node
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
 */

package auth

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAuth_AuthorizationRequestProfile(t *testing.T) {
	t.Run("built-in aet", func(t *testing.T) {
		params, ok := (&Auth{}).AuthorizationRequestProfile("aet")
		require.True(t, ok)
		assert.Equal(t, []string{"SmartCard"}, params["auth_method"])
		assert.Equal(t, []string{"openid profile api"}, params["scope"])
	})
	t.Run("unknown profile returns false", func(t *testing.T) {
		params, ok := (&Auth{}).AuthorizationRequestProfile("does-not-exist")
		assert.False(t, ok)
		assert.Nil(t, params)
	})
	t.Run("operator config merges over the built-in per key", func(t *testing.T) {
		a := &Auth{config: Config{Experimental: ExperimentalConfig{Profiles: map[string]ProfileConfig{
			"aet": {AuthorizationRequest: map[string][]string{"scope": {"openid"}}},
		}}}}
		params, ok := a.AuthorizationRequestProfile("aet")
		require.True(t, ok)
		assert.Equal(t, []string{"openid"}, params["scope"])          // overridden by operator
		assert.Equal(t, []string{"SmartCard"}, params["auth_method"]) // kept from built-in
	})
	t.Run("operator-only profile", func(t *testing.T) {
		a := &Auth{config: Config{Experimental: ExperimentalConfig{Profiles: map[string]ProfileConfig{
			"custom": {AuthorizationRequest: map[string][]string{"foo": {"bar", "baz"}}},
		}}}}
		params, ok := a.AuthorizationRequestProfile("custom")
		require.True(t, ok)
		assert.Equal(t, []string{"bar", "baz"}, params["foo"])
	})
}

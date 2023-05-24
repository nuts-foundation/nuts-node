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
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

func Test_DefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	assert.Equal(t, 4, cfg.MaxUpdateFailHours)
	assert.True(t, cfg.Softfail)
	require.NotNil(t, cfg.Denylist)
	assert.Empty(t, cfg.Denylist.TrustedSigner)
	assert.Empty(t, cfg.Denylist.URL)
}

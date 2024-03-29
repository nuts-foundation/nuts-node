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

//go:build jwx_es256k

package oauth

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestES256k(t *testing.T) {
	t.Run("supported formats specifies ES256K", func(t *testing.T) {
		assert.Contains(t, DefaultOpenIDSupportedFormats()["jwt_vp_json"]["alg_values_supported"], "ES256K")
		assert.Contains(t, DefaultOpenIDSupportedFormats()["jwt_vc_json"]["alg_values_supported"], "ES256K")
	})
}

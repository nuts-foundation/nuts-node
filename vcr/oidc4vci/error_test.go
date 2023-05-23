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

package oidc4vci

import (
	"errors"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestError_Error(t *testing.T) {
	t.Run("with underlying error", func(t *testing.T) {
		assert.EqualError(t, Error{Err: errors.New("token has expired"), Code: InvalidToken}, "invalid_token - token has expired")
	})
	t.Run("without underlying error", func(t *testing.T) {
		assert.EqualError(t, Error{Code: InvalidToken}, "invalid_token")
	})
}

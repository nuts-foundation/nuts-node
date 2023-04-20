/*
 * Nuts node
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
 */

package selfsigned

import (
	"github.com/magiconair/properties/assert"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/auth/contract"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestSessionStore_VerifyVP(t *testing.T) {
	t.Run("always returns invalid VerificationResult", func(t *testing.T) {
		ss := NewService(nil)

		result, err := ss.VerifyVP(vc.VerifiablePresentation{}, nil)

		require.NoError(t, err)
		assert.Equal(t, contract.Invalid, result.Validity())
	})
}

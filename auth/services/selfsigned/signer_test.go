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
	"github.com/stretchr/testify/require"
	"testing"
)

func TestSelfSigned_StartSigningSession(t *testing.T) {
	t.Run("add params to session", func(t *testing.T) {
		params := map[string]interface{}{
			"employer": "did:nuts:a",
			"employee": struct {
				Identifier string `json:"identifier"`
				RoleName   string `json:"roleName"`
				Initials   string `json:"initials"`
				FamilyName string `json:"familyName"`
			}{
				"123",
				"role",
				"T",
				"Tester",
			},
		}
		ss := NewSessionStore().(sessionStore)

		sp, err := ss.StartSigningSession("contract", params)
		require.NoError(t, err)
		session := ss.sessions[sp.SessionID()]
		require.NotNil(t, session)
		assert.Equal(t, "contract", session.contract)
		assert.Equal(t, SessionCreated, session.status)
		assert.Equal(t, "did:nuts:a", session.Employer)
		assert.Equal(t, "Tester", session.Employee.FamilyName)
		assert.Equal(t, "T", session.Employee.Initials)
		assert.Equal(t, "123", session.Employee.Identifier)
		assert.Equal(t, "role", session.Employee.RoleName)
	})
}

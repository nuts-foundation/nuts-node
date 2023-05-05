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

package types

import (
	"github.com/stretchr/testify/require"
	"testing"
	"time"
)

func TestSession_HumanReadableContract(t *testing.T) {
	t.Run("ok - it removes the contract identifier", func(t *testing.T) {
		session := Session{
			Contract: "NL:LoginContract:v3 Ik verklaar te handelen namens x",
		}
		actual := session.HumanReadableContract()
		expected := "Ik verklaar te handelen namens x"
		if actual != expected {
			t.Errorf("expected %s, got %s", expected, actual)
		}
	})
}

func TestSession_CredentialSubject(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		s := Session{
			ExpiresAt: time.Now(),
			Contract:  "NL:LoginContract:v3 Ik verklaar te handelen namens x",
			Secret:    "secret value",
			Status:    SessionCreated,
			Employer:  "did:nuts:123",
			Employee: Employee{
				Identifier: "123",
				RoleName:   "Verpleegkundige",
				Initials:   "T",
				FamilyName: "Tester",
			},
		}
		res := s.CredentialSubject()
		require.Len(t, res, 1)
		subject := res[0].(map[string]interface{})
		// subject is an organization and contains information about the employer
		require.Equal(t, "did:nuts:123", subject["id"])
		require.Equal(t, "Organization", subject["type"])

		// member is an employeeRole and contains information about the relationship between employer and employee
		member := subject["member"].(map[string]interface{})
		require.Equal(t, "EmployeeRole", member["type"])
		require.Equal(t, "123", member["identifier"])
		require.Equal(t, "Verpleegkundige", member["roleName"])

		// memberMember is a person and contains information about the employee
		memberMember := member["member"].(map[string]interface{})
		require.Equal(t, "Person", memberMember["type"])
		require.Equal(t, "T", memberMember["initials"])
		require.Equal(t, "Tester", memberMember["familyName"])
	})
}

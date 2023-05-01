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

package web

import (
	"bytes"
	"github.com/nuts-foundation/nuts-node/auth/services/selfsigned/types"
	"github.com/stretchr/testify/require"
	"testing"
	"time"
)

func TestRenderTemplate(t *testing.T) {
	buf := new(bytes.Buffer)
	err := renderTemplate("employee_identity", "nl", types.Session{
		ExpiresAt: time.Now(),
		Contract:  "Hello, World!",
		Secret:    "secret",
		Status:    "pending",
		Employer:  "Darth Vader",
		Employee: types.Employee{
			Identifier: "johndoe@example.com",
			RoleName:   "Administrator",
			Initials:   "J",
			FamilyName: "Doe",
		},
	}, buf)
	require.NoError(t, err)
	println(buf.String())
}

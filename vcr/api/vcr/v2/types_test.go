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

package v2

import (
	"github.com/nuts-foundation/nuts-node/json"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
	"time"
)

func Test_Marshalling(t *testing.T) {
	t.Run("IssueVC200JSONResponse", func(t *testing.T) {
		r := IssueVC200JSONResponse{
			CredentialSubject: []interface{}{
				map[string]interface{}{
					"id": "did:nuts:123",
				}},
		}
		data, _ := json.Marshal(r)
		result := make(map[string]interface{}, 0)
		err := json.Unmarshal(data, &result)
		require.NoError(t, err)

		assert.IsType(t, make(map[string]interface{}, 0), result["credentialSubject"]) // single entry should not end up as slice
	})
	t.Run("ResolveVC200JSONResponse", func(t *testing.T) {
		r := ResolveVC200JSONResponse{
			CredentialSubject: []interface{}{
				map[string]interface{}{
					"id": "did:nuts:123",
				}},
		}
		data, _ := json.Marshal(r)
		result := make(map[string]interface{}, 0)
		err := json.Unmarshal(data, &result)
		require.NoError(t, err)

		assert.IsType(t, make(map[string]interface{}, 0), result["credentialSubject"]) // single entry should not end up as slice
	})
	t.Run("CreateVP200JSONResponse", func(t *testing.T) {
		issuanceDate := time.Now()
		r := CreateVP200JSONResponse(VerifiablePresentation{
			VerifiableCredential: []VerifiableCredential{
				{
					IssuanceDate: issuanceDate,
				},
			},
		})
		data, _ := json.Marshal(r)
		result := make(map[string]interface{}, 0)
		err := json.Unmarshal(data, &result)
		require.NoError(t, err)

		assert.IsType(t, make(map[string]interface{}, 0), result["verifiableCredential"]) // single entry should not end up as slice
	})
}

/*
 * Nuts node
 * Copyright (C) 2022 Nuts community
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

package events

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/nuts-foundation/nuts-node/network/dag"
	"github.com/stretchr/testify/assert"
)

var testJSON = `
{
	"transaction":"eyJhbGciOiJFUzI1NiIsImNyaXQiOlsic2lndCIsInZlciIsInByZXZzIiwia2lkIl0sImN0eSI6ImFwcGxpY2F0aW9uL2RpZCtqc29uIiwia2lkIjoiMCIsImxjIjowLCJwcmV2cyI6W10sInNpZ3QiOjE2NTA2NDExMDEsInZlciI6MX0.ZGYzZjYxOTgwNGE5MmZkYjQwNTcxOTJkYzQzZGQ3NDhlYTc3OGFkYzUyYmM0OThjZTgwNTI0YzAxNGI4MTExOQ.G-AlXNU75ip0fZQPYd_KF0VYesxoqUWo4ut6dFF76d2r5YEPAGtLtRKaEOWwSnC-aZO6GAeZLnfvAEaBoujH2w",
	"payload":"cGF5bG9hZA=="
}
`

func TestTransactionWithPayload_MarshalJSON(t *testing.T) {
	tx, _, _ := dag.CreateTestTransaction(0)
	twp := TransactionWithPayload{
		Transaction: tx,
		Payload:     []byte("payload"),
	}

	bytes, err := json.Marshal(twp)
	require.NoError(t, err)

	assert.Contains(t, string(bytes), "\"transaction\":\"eyJhbGciOiJFUzI1NiIsImNyaXQiOlsic2lndCIsInZlciIsInB")
	assert.Contains(t, string(bytes), "\"payload\":\"cGF5bG9hZA==\"")
}

func TestTransactionWithPayload_UnmarshalJSON(t *testing.T) {
	twp := TransactionWithPayload{}
	err := json.Unmarshal([]byte(testJSON), &twp)
	require.NoError(t, err)

	// sha256 of "payload"
	assert.Equal(t, "df3f619804a92fdb4057192dc43dd748ea778adc52bc498ce80524c014b81119", twp.Transaction.PayloadHash().String())
	assert.Equal(t, "payload", string(twp.Payload))
}

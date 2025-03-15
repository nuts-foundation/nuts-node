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
	"encoding/base64"
	"github.com/nuts-foundation/nuts-node/json"

	"github.com/nuts-foundation/nuts-node/network/dag"
)

// TransactionWithPayload holds the transaction and byte payload
// It serializes as JSON where the transaction is serialized as JWS string and the payload as base64 encoded string
type TransactionWithPayload struct {
	Transaction dag.Transaction
	Payload     []byte
}

type transactionWithPayloadHelper struct {
	Transaction string `json:"transaction"`
	Payload     string `json:"payload"`
}

func (t TransactionWithPayload) MarshalJSON() ([]byte, error) {
	helper := transactionWithPayloadHelper{
		Transaction: string(t.Transaction.Data()),
		Payload:     base64.StdEncoding.EncodeToString(t.Payload),
	}

	return json.Marshal(helper)
}

func (t *TransactionWithPayload) UnmarshalJSON(bytes []byte) error {
	var err error
	helper := transactionWithPayloadHelper{}
	if err = json.Unmarshal(bytes, &helper); err != nil {
		return err
	}

	t.Transaction, err = dag.ParseTransaction([]byte(helper.Transaction))
	if err != nil {
		return err
	}
	t.Payload, err = base64.StdEncoding.DecodeString(helper.Payload)

	return err
}

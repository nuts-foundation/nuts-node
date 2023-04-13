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
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"github.com/nuts-foundation/nuts-node/auth/contract"
	"github.com/nuts-foundation/nuts-node/auth/services"
)

func (v SelfSigned) SigningSessionStatus(sessionID string) (contract.SigningSessionResult, error) {
	s, ok := v.Sessions[sessionID]
	if !ok {
		return nil, services.ErrSessionNotFound
	}
	return signingSessionResult{
		id:      sessionID,
		status:  s.status,
		request: s.contract,
	}, nil
}

func (v SelfSigned) StartSigningSession(rawContractText string, params map[string]interface{}) (contract.SessionPointer, error) {
	sessionBytes := make([]byte, 16)
	rand.Reader.Read(sessionBytes)

	sessionID := hex.EncodeToString(sessionBytes)
	s := session{
		contract: rawContractText,
		status:   SessionCreated,
	}
	marshalled, err := json.Marshal(params)
	if err != nil {
		return nil, err
	}
	if err = json.Unmarshal(marshalled, &s); err != nil {
		return nil, err
	}
	v.Sessions[sessionID] = s

	return sessionPointer{
		sessionID: sessionID,
		html:      "<html></html>", // placeholder, convert to template
	}, nil
}

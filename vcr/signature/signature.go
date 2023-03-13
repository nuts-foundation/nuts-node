/*
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

package signature

import (
	"context"

	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/nuts-node/crypto"
)

// W3idSecurityV1Context defines the v1 of the w3id json-ld context
var W3idSecurityV1Context = ssi.MustParseURI("https://w3id.org/security/v1")

// W3idSecurityV2Context defines the v2 of the w3id json-ld context
var W3idSecurityV2Context = ssi.MustParseURI("https://w3id.org/security/v2")

// JSONWebSignature2020Context defines the JsonWebSignature2020 json-ld context
var JSONWebSignature2020Context = ssi.MustParseURI("https://w3c-ccg.github.io/lds-jws2020/contexts/lds-jws2020-v1.json")

// Suite is an interface which defines the methods a signature suite implementation should implement.
type Suite interface {
	Sign(ctx context.Context, doc []byte, key crypto.Key) ([]byte, error)
	CanonicalizeDocument(doc interface{}) ([]byte, error)
	CalculateDigest(doc []byte) []byte
	GetType() ssi.ProofType
}

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
	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/nuts-node/crypto"
)

// Suite is an interface which defines the methods a signature suite implementation should implement.
type Suite interface {
	Sign(doc []byte, key crypto.Key) ([]byte, error)
	CanonicalizeDocument(doc interface{}) ([]byte, error)
	CalculateDigest(doc []byte) []byte
	GetType() ssi.ProofType
	GetProofValueKey() string
}

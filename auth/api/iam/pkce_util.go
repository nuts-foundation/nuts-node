/*
 * Copyright (C) 2024 Nuts community
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

package iam

import (
	"crypto/sha256"
	"encoding/base64"
	nutsCrypto "github.com/nuts-foundation/nuts-node/crypto"
)

// PKCEParams contains the PKCE parameters so they can be stored in both the client and server side session.
type PKCEParams struct {
	Challenge       string
	ChallengeMethod string
	Verifier        string
}

func generatePKCEParams() PKCEParams {
	verifier := nutsCrypto.GenerateNonce()
	sha := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sha[:])
	return PKCEParams{
		Challenge:       challenge,
		ChallengeMethod: "S256",
		Verifier:        verifier,
	}
}

func validatePKCEParams(params PKCEParams) bool {
	switch params.ChallengeMethod {
	case "S256":
		sha := sha256.Sum256([]byte(params.Verifier))
		challenge := base64.RawURLEncoding.EncodeToString(sha[:])
		return challenge == params.Challenge
	default:
		return false
	}
}

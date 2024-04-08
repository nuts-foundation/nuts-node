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

package iam

import (
	"crypto/sha256"
	"encoding/base64"
	"github.com/nuts-foundation/nuts-node/crypto"
)

// PKCEParams represents the parameters used for Proof Key for Code Exchange.
// The concept behind the PKCE is that the initial request contains a Challenge and
// ChallengeMethod parameter. The challenge is the result of a hash of the Verifier.
// In the final request, the holder can prove its ownership by providing the value
// of the Verifier, the verifying party now can verify the holder by re-generating
// the hash with the value of the Verifier and checking it against the original
// Challenge.
type PKCEParams struct {
	// The Challenge is send in the first request, based on a hash of the verifier. The
	// ChallengeMethod defines the hash method.
	Challenge string
	// The ChallengeMethod denotes the hash function used to generate the challenge.
	ChallengeMethod string
	// Verifier is send in the final request, this proves the ownership of the prior
	// Challenge, as the Challenge is a hash of the original Verifier.
	Verifier string
}

func generatePKCEParams() PKCEParams {
	verifier := crypto.GenerateNonce()
	sha := sha256.Sum256([]byte(verifier))
	challenge := base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(sha[:])
	return PKCEParams{
		Challenge:       challenge,
		ChallengeMethod: "S256",
		Verifier:        verifier,
	}
}

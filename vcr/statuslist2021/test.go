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

package statuslist2021

import (
	"github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/vc"
	"testing"
	"time"
)

func ValidStatusList2021Credential(_ testing.TB) vc.VerifiableCredential {
	id := ssi.MustParseURI("https://example.com/credentials/status/3")
	validFrom := time.Now()
	validUntilTomorrow := validFrom.Add(24 * time.Hour)
	return vc.VerifiableCredential{
		Context:          []ssi.URI{vc.VCContextV1URI(), ContextURI},
		ID:               &id,
		Type:             []ssi.URI{vc.VerifiableCredentialTypeV1URI(), ssi.MustParseURI(CredentialType)},
		Issuer:           ssi.MustParseURI("did:example:12345"),
		ValidFrom:        &validFrom,
		ValidUntil:       &validUntilTomorrow,
		CredentialStatus: nil,
		CredentialSubject: []any{&CredentialSubject{
			Id:            "https://example-com/status/3#list",
			Type:          CredentialSubjectType,
			StatusPurpose: "revocation",
			EncodedList:   "H4sIAAAAAAAA_-zAsQAAAAACsNDypwqjZ2sAAAAAAAAAAAAAAAAAAACAtwUAAP__NxdfzQBAAAA=", // has bit 1 set to true
		}},
		Proof: []any{vc.Proof{}},
	}
}

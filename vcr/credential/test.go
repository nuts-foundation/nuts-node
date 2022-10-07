/*
 * Nuts node
 * Copyright (C) 2021 Nuts community
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

package credential

import (
	"time"

	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/vdr"
)

func validV1NutsAuthorizationCredential() *vc.VerifiableCredential {
	id := stringToURI(vdr.TestDIDA.String() + "#1")
	return &vc.VerifiableCredential{
		Context:      []ssi.URI{vc.VCContextV1URI(), NutsV1ContextURI},
		ID:           &id,
		Type:         []ssi.URI{*NutsAuthorizationCredentialTypeURI, vc.VerifiableCredentialTypeV1URI()},
		Issuer:       stringToURI(vdr.TestDIDA.String()),
		IssuanceDate: time.Now(),
		CredentialSubject: []interface{}{
			NutsAuthorizationCredentialSubject{
				ID:           vdr.TestDIDB.String(),
				PurposeOfUse: "eTransfer",
				Resources: []Resource{
					{
						Path:        "/composition/1",
						Operations:  []string{"read"},
						UserContext: true,
					},
				},
			},
		},
		Proof: []interface{}{vc.Proof{}},
	}
}

func validV2NutsAuthorizationCredential(credentialSubject NutsAuthorizationCredentialSubject) *vc.VerifiableCredential {
	id := stringToURI(vdr.TestDIDA.String() + "#1")
	return &vc.VerifiableCredential{
		Context:           []ssi.URI{vc.VCContextV1URI(), NutsV2ContextURI},
		ID:                &id,
		Type:              []ssi.URI{*NutsAuthorizationCredentialTypeURI, vc.VerifiableCredentialTypeV1URI()},
		Issuer:            stringToURI(vdr.TestDIDA.String()),
		IssuanceDate:      time.Now(),
		CredentialSubject: []interface{}{credentialSubject},
		Proof:             []interface{}{vc.Proof{}},
	}
}

func validV2ImpliedNutsAuthorizationCredential() *vc.VerifiableCredential {
	credentialSubject := NutsAuthorizationCredentialSubject{
		ID: vdr.TestDIDB.String(),
		LegalBase: &LegalBase{
			ConsentType: "implied",
		},
		PurposeOfUse: "eTransfer",
		Resources: []Resource{
			{
				Path:        "/composition/1",
				Operations:  []string{"read"},
				UserContext: true,
			},
		},
	}
	return validV2NutsAuthorizationCredential(credentialSubject)
}

func ValidV2ExplicitNutsAuthorizationCredential() *vc.VerifiableCredential {
	patient := "urn:oid:2.16.840.1.113883.2.4.6.3:123456780"
	credentialSubject := NutsAuthorizationCredentialSubject{
		ID: vdr.TestDIDB.String(),
		LegalBase: &LegalBase{
			ConsentType: "explicit",
			Evidence: &Evidence{
				Path: "/1.pdf",
				Type: "application/pdf",
			},
		},
		PurposeOfUse: "careViewer",
		Subject:      &patient,
		Resources: []Resource{
			{
				Path:        "/Task/1",
				Operations:  []string{"read", "update"},
				UserContext: false,
			},
		},
	}
	return validV2NutsAuthorizationCredential(credentialSubject)
}

func stringToURI(input string) ssi.URI {
	return ssi.MustParseURI(input)
}

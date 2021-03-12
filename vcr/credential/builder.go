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
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/nuts-foundation/go-did"
)

// Builder is an abstraction for extending a partial VC into a fully valid VC
type Builder interface {
	// Type returns the matching Verifiable Credential type
	Type() string
	// Fill sets the defaults for common fields
	Fill(vc *did.VerifiableCredential)
}

// defaultBuilder fills in the type, issuanceDate and context
type defaultBuilder struct {
	vcType string
}

var nowFunc = time.Now

func (d defaultBuilder) Fill(vc *did.VerifiableCredential) {
	vc.Context = []did.URI{did.VCContextV1URI(), *NutsContextURI}

	defaultType := did.VerifiableCredentialTypeV1URI()
	if !vc.IsType(defaultType) {
		vc.Type = append(vc.Type, defaultType)
	}

	builderType, _ := did.ParseURI(d.vcType)
	if !vc.IsType(*builderType) {
		vc.Type = append(vc.Type, *builderType)
	}
	vc.IssuanceDate = nowFunc()
	vc.ID = generateID(vc.Issuer)

	return
}

func (d defaultBuilder) Type() string {
	return d.vcType
}

func generateID(issuer did.URI) *did.URI {
	id := fmt.Sprintf("%s#%s", issuer.String(), uuid.New().String())
	u, _ := did.ParseURI(id)
	return u
}

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
	ssi "github.com/nuts-foundation/go-did"
)

const (
	// NutsOrganizationCredentialType is the VC type for a NutsOrganizationCredentialType
	NutsOrganizationCredentialType = "NutsOrganizationCredential"
	// NutsContext is the nuts specific json-ld context
	NutsContext = "https://nuts.nl/credentials/v1"
)

var (
	// NutsOrganizationCredentialTypeURI is the VC type for a NutsOrganizationCredentialType as URI
	NutsOrganizationCredentialTypeURI, _ = ssi.ParseURI(NutsOrganizationCredentialType)
	// NutsContextURI is the nuts specific json-ld context as URI
	NutsContextURI, _ = ssi.ParseURI(NutsContext)
)

// NutsOrganizationCredentialSubject defines the CredentialSubject struct for the NutsOrganizationCredentialType
type NutsOrganizationCredentialSubject struct {
	ID           string            `json:"id"`
	Organization map[string]string `json:"organization"`
}

// BaseCredentialSubject defines the CredentialSubject struct for fields that are shared amongst all CredentialSubjects
type BaseCredentialSubject struct {
	ID string `json:"id"`
}

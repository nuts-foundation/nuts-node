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
	// NutsOrganizationCredentialType is the VC type for a NutsOrganizationCredential
	NutsOrganizationCredentialType = "NutsOrganizationCredential"
	// NutsAuthorizationCredentialType is the VC type for a NutsAuthorizationCredential
	NutsAuthorizationCredentialType = "NutsAuthorizationCredential"
	// NutsV1Context is the nuts V1 json-ld context
	NutsV1Context = "https://nuts.nl/credentials/v1"
)

var (
	// NutsOrganizationCredentialTypeURI is the VC type for a NutsOrganizationCredentialType as URI
	NutsOrganizationCredentialTypeURI, _ = ssi.ParseURI(NutsOrganizationCredentialType)
	// NutsAuthorizationCredentialTypeURI is the VC type for a NutsAuthorizationCredentialType as URI
	NutsAuthorizationCredentialTypeURI, _ = ssi.ParseURI(NutsAuthorizationCredentialType)
	// NutsV1ContextURI is the nuts V1 json-ld context as URI
	NutsV1ContextURI = ssi.MustParseURI(NutsV1Context)
)

const (
	// CredentialSubjectPath represents the JSON path to the holder of the VC
	CredentialSubjectPath = "credentialSubject.id"
	// RevocationSubjectPath represents the JSON path to the subject of a revocation, typically the VC id
	RevocationSubjectPath = "subject"
)

// NutsOrganizationCredentialSubject defines the CredentialSubject struct for the NutsOrganizationCredential
type NutsOrganizationCredentialSubject struct {
	ID           string            `json:"id"`
	Organization map[string]string `json:"organization"`
}

// NutsAuthorizationCredentialSubject defines the CredentialSubject struct for the NutsAuthorizationCredential
type NutsAuthorizationCredentialSubject struct {
	// ID contains the DID of the subject
	ID string `json:"id"`
	// PurposeOfUse refers to the Bolt access policy
	PurposeOfUse string `json:"purposeOfUse"`
	// Resources contains additional individual resources that can be accessed.
	Resources []Resource `json:"resources,omitempty"`
	// Subject contains a URN referring to the subject of care (not the credential subject)
	Subject *string `json:"subject,omitempty"`
}

// Resource defines a single accessbile resource
type Resource struct {
	// Path defines the path of the resource relative to the service base URL.
	// Which service acts as base URL is described by the Bolt.
	Path string `json:"path"`
	// Operations define which operations are allowed on the resource.
	Operations []string `json:"operations"`
	// UserContext defines if a user login contract is required for the resource.
	UserContext bool `json:"userContext"`
	// AssuranceLevel defines the assurance level required for the resource (low, substantial, high).
	// Should be set if userContext = true, defaults to low
	AssuranceLevel *string `json:"assuranceLevel"`
}

// BaseCredentialSubject defines the CredentialSubject struct for fields that are shared amongst all CredentialSubjects
type BaseCredentialSubject struct {
	ID string `json:"id"`
}

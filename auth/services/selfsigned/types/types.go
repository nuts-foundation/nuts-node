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

package types

import (
	"encoding/json"
	"github.com/nuts-foundation/nuts-node/vcr/credential"
	"strings"
	"time"
)

type SessionStore interface {
	Store(sessionID string, session Session)
	Load(sessionID string) (Session, bool)
	CheckAndSetStatus(sessionID string, expectedStatus, status string) bool
	Delete(sessionID string)
}

// Session contains the contract text and Session signing Status
type Session struct {
	ExpiresAt time.Time
	Contract  string
	Secret    string
	Status    string
	Employer  string
	Employee  Employee
}

func (s Session) CredentialSubject() []interface{} {
	subject := EmployeeIdentityCredentialSubject{
		BaseCredentialSubject: credential.BaseCredentialSubject{
			ID: s.Employer,
		},
		Type: "Organization",
		Member: EmployeeIdentityCredentialMember{
			Identifier: s.Employee.Identifier,
			Member: EmployeeIdentityCredentialMemberMember{
				FamilyName: s.Employee.FamilyName,
				Initials:   s.Employee.Initials,
				Type:       "Person",
			},
			RoleName: s.Employee.RoleName,
			Type:     "EmployeeRole",
		},
	}
	data, _ := json.Marshal(subject)
	result := map[string]interface{}{}
	_ = json.Unmarshal(data, &result)
	return []interface{}{result}
}

// HumanReadableContract returns the contract text without the contract type (e.g. "NL:LoginContract:v3")
func (s Session) HumanReadableContract() string {
	return s.Contract[strings.Index(s.Contract, " ")+1:]
}

type Employee struct {
	Identifier string
	Initials   string
	FamilyName string
	RoleName   *string
}

type EmployeeIdentityCredentialSubject struct {
	credential.BaseCredentialSubject
	Type   string                           `json:"type"`
	Member EmployeeIdentityCredentialMember `json:"member"`
}

type EmployeeIdentityCredentialMember struct {
	Identifier string                                 `json:"identifier"`
	Member     EmployeeIdentityCredentialMemberMember `json:"member"`
	RoleName   *string                                `json:"roleName,omitempty"`
	Type       string                                 `json:"type"`
}

type EmployeeIdentityCredentialMemberMember struct {
	FamilyName string `json:"familyName"`
	Initials   string `json:"initials"`
	Type       string `json:"type"`
}

// SessionCreated represents the session state after creation
const SessionCreated = "created"

// SessionInProgress represents the session state after rendering the html
const SessionInProgress = "in-progress"

// SessionCompleted represents the session state after the user has accepted the contract
const SessionCompleted = "completed"

const SessionVPRequested = "vp-requested"

const SessionCancelled = "cancelled"

const SessionErrored = "errored"

const SessionExpired = "expired"

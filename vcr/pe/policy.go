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

package pe

// PEXPolicy defines the intended audience for a PresentationDefinition
type PEXPolicy struct {
	AudienceType           AudienceType           `json:"audience_type"`
	PresentationDefinition PresentationDefinition `json:"presentation_definition"`
}

// AudienceType defines the intended audience for a PresentationDefinition
type AudienceType string

const (
	// AudienceTypeOrganization is used in a PEXPolicy when the PresentationDefinition is intended for an organization
	AudienceTypeOrganization = AudienceType("organization")
	// AudienceTypeUser is used in a PEXPolicy when the PresentationDefinition is intended for a user
	AudienceTypeUser = AudienceType("user")
)

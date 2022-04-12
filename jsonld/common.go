/*
 * Nuts node
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

package jsonld

var (
	// OrganizationNamePath contains the JSON-LD search path for finding an organization name
	OrganizationNamePath = NewPath("https://www.w3.org/2018/credentials#credentialSubject", "http://schema.org/organization", "http://schema.org/legalname")
	// OrganizationCityPath contains the JSON-LD search path for finding an organization city
	OrganizationCityPath = NewPath("https://www.w3.org/2018/credentials#credentialSubject", "http://schema.org/organization", "http://schema.org/city")
	// CredentialSubjectPath contains the JSON-LD search path for the credential subject ID
	CredentialSubjectPath = NewPath("https://www.w3.org/2018/credentials#credentialSubject")
	// CredentialIssuerPath contains the JSON-LD search path for the credential issuer
	CredentialIssuerPath = NewPath("https://www.w3.org/2018/credentials#issuer")
)

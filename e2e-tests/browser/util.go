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

//go:build e2e_tests

package browser

import (
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/e2e-tests/browser/rfc019_selfsigned/apps"
	vcrAPI "github.com/nuts-foundation/nuts-node/vcr/api/vcr/v2"
)

func IssueOrganizationCredential(organization *did.Document, name, city string) error {
	vcrClient := vcrAPI.HTTPClient{ClientConfig: apps.NodeClientConfig}
	request := vcrAPI.IssueVCRequest{
		Issuer: organization.ID.String(),
		CredentialSubject: map[string]interface{}{
			"id": organization.ID.String(),
			"organization": map[string]interface{}{
				"name": name,
				"city": city,
			},
		},
	}
	switch organization.ID.Method {
	case "web":
		withStatusList2021Revocation := false
		request.WithStatusList2021Revocation = &withStatusList2021Revocation
	case "nuts":
		visibility := vcrAPI.Public
		request.Visibility = &visibility
	}
	err := request.Type.FromIssueVCRequestType1(vcrAPI.IssueVCRequestType1{"VerifiableCredential", "NutsOrganizationCredential"})
	if err != nil {
		return err
	}
	issuedCredential, err := vcrClient.IssueVC(request)
	if err != nil {
		return err
	}
	if organization.ID.Method == "web" {
		// Need to load it into tbe wallet
		return vcrClient.LoadVC(organization.ID, *issuedCredential)
	}
	return nil
}

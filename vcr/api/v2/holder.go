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

package v2

import (
	"encoding/json"
	"net/http"

	"github.com/labstack/echo/v4"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/vcr/concept"
	"github.com/nuts-foundation/nuts-node/vcr/credential"
)

// SearchVCs checks the context used in the JSON-LD query, based on the contents it maps to a non-JSON-LD query
// After V1, this needs to be remapped to a DB search that supports native JSON-LD
func (w *Wrapper) SearchVCs(ctx echo.Context) error {
	var request SearchVCRequest
	err := ctx.Bind(&request)
	if err != nil {
		return core.InvalidInputError("failed to parse request body: %w", err)
	}

	untrusted := false
	if request.SearchOptions != nil && request.SearchOptions.AllowUntrustedIssuer != nil {
		untrusted = *request.SearchOptions.AllowUntrustedIssuer
	}

	query, _ := json.Marshal(request.Query)
	var types []string
	for _, curr := range request.Query.Type {
		types = append(types, curr.String())
	}
	for _, c := range types {
		switch c {
		case credential.NutsOrganizationCredentialType:
			return w.searchOrgs(ctx, untrusted, query)
		case credential.NutsAuthorizationCredentialType:
			return w.searchAuths(ctx, untrusted, query)
		}
	}

	return core.InvalidInputError("given type not supported")
}

func (w *Wrapper) searchOrgs(ctx echo.Context, allowUntrusted bool, body []byte) error {
	// some helper structs
	type helper struct {
		CredentialSubject struct {
			ID           string `json:"id"`
			Organization struct {
				Name string `json:"name"`
				City string `json:"city"`
			} `json:"organization"`
		} `json:"credentialSubject"`
	}

	ldQuery := helper{}
	if err := json.Unmarshal(body, &ldQuery); err != nil {
		return core.InvalidInputError("failed to unmarshall JSON request body: %w", err)
	}

	// convert to query
	query, err := w.VCR.Registry().QueryFor(concept.OrganizationConcept)
	if err != nil {
		return err
	}
	if ldQuery.CredentialSubject.Organization.Name != "" {
		query.AddClause(concept.Prefix("organization.name", ldQuery.CredentialSubject.Organization.Name))
	}
	if ldQuery.CredentialSubject.Organization.City != "" {
		query.AddClause(concept.Prefix("organization.city", ldQuery.CredentialSubject.Organization.City))
	}
	if ldQuery.CredentialSubject.ID != "" {
		query.AddClause(concept.Eq("subject", ldQuery.CredentialSubject.ID))
	}

	results, err := w.VCR.Search(ctx.Request().Context(), query, allowUntrusted, nil)
	if err != nil {
		return err
	}

	return ctx.JSON(http.StatusOK, results)
}

func (w *Wrapper) searchAuths(ctx echo.Context, allowUntrusted bool, body []byte) error {
	// some helper structs that reflect current required query params
	type helper struct {
		CredentialSubject struct {
			ID           string `json:"id"`
			PurposeOfUse string `json:"purposeOfUse"`
			Subject      string `json:"subject"`
			Resources    struct {
				Path string `json:"path"`
			} `json:"resources"`
		} `json:"credentialSubject"`
	}

	ldQuery := helper{}
	if err := json.Unmarshal(body, &ldQuery); err != nil {
		return core.InvalidInputError("failed to unmarshall JSON request body: %w", err)
	}

	// convert to query
	query, err := w.VCR.Registry().QueryFor(concept.AuthorizationConcept)
	if err != nil {
		return err
	}
	if ldQuery.CredentialSubject.ID != "" {
		query.AddClause(concept.Eq("credentialSubject.id", ldQuery.CredentialSubject.ID))
	}
	if ldQuery.CredentialSubject.PurposeOfUse != "" {
		query.AddClause(concept.Eq("credentialSubject.purposeOfUse", ldQuery.CredentialSubject.PurposeOfUse))
	}
	if ldQuery.CredentialSubject.Subject != "" {
		query.AddClause(concept.Eq("credentialSubject.subject", ldQuery.CredentialSubject.Subject))
	}
	if ldQuery.CredentialSubject.Resources.Path != "" {
		query.AddClause(concept.Eq("credentialSubject.resources.#.path", ldQuery.CredentialSubject.Resources.Path))
	}

	results, err := w.VCR.Search(ctx.Request().Context(), query, allowUntrusted, nil)
	if err != nil {
		return err
	}

	return ctx.JSON(http.StatusOK, results)
}

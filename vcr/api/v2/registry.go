/*
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
	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/vcr/concept"
	"net/http"

	"github.com/labstack/echo/v4"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/vcr/credential"
)

// ResolveVC handles the API request for resolving a VC
func (w *Wrapper) ResolveVC(ctx echo.Context, id string) error {
	vcID, err := ssi.ParseURI(id)
	if err != nil {
		return core.InvalidInputError("invalid credential id: %w", err)
	}
	result, err := w.VCR.Resolve(*vcID, nil)
	if err != nil {
		return err
	}
	return ctx.JSON(http.StatusOK, *result)
}

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

	if len(request.Query.CredentialSubject) > 1 {
		return core.InvalidInputError("can't match on multiple VC subjects")
	}

	var types []string
	for _, curr := range request.Query.Type {
		types = append(types, curr.String())
	}
	for _, c := range types {
		switch c {
		case credential.NutsOrganizationCredentialType:
			return w.searchOrgs(ctx, untrusted, request.Query)
		case credential.NutsAuthorizationCredentialType:
			return w.searchAuths(ctx, untrusted, request.Query)
		}
	}

	return core.InvalidInputError("given type not supported")
}

func (w *Wrapper) searchOrgs(ctx echo.Context, allowUntrusted bool, vcQuery vc.VerifiableCredential) error {
	// credentialSubject struct that reflect current supported query params
	type credentialSubject struct {
		ID           string `json:"id"`
		Organization struct {
			Name string `json:"name"`
			City string `json:"city"`
		} `json:"organization"`
	}

	var subjectsQuery []credentialSubject
	if err := vcQuery.UnmarshalCredentialSubject(&subjectsQuery); err != nil {
		return core.InvalidInputError("failed to unmarshall VC subject: %w", err)
	}

	// convert to query
	query, err := w.VCR.Registry().QueryFor(concept.OrganizationConcept)
	if err != nil {
		return err
	}
	if vcQuery.Issuer.String() != "" {
		query.AddClause(concept.Eq("issuer", vcQuery.Issuer.String()))
	}
	if len(subjectsQuery) > 0 {
		subjectQuery := subjectsQuery[0]
		if subjectQuery.Organization.Name != "" {
			query.AddClause(concept.Prefix("organization.name", subjectQuery.Organization.Name))
		}
		if subjectQuery.Organization.City != "" {
			query.AddClause(concept.Prefix("organization.city", subjectQuery.Organization.City))
		}
		if subjectQuery.ID != "" {
			query.AddClause(concept.Eq("credentialSubject.id", subjectQuery.ID))
		}
	}

	results, err := w.VCR.Search(ctx.Request().Context(), query, allowUntrusted, nil)
	if err != nil {
		return err
	}
	searchResults, err := w.vcsWithRevocationsToSearchResults(results)
	if err != nil {
		return err
	}
	return ctx.JSON(http.StatusOK, SearchVCResults{searchResults})
}

func (w *Wrapper) searchAuths(ctx echo.Context, allowUntrusted bool, vcQuery vc.VerifiableCredential) error {
	// credentialSubject struct that reflect current supported query params
	type credentialSubject struct {
		ID           string `json:"id"`
		PurposeOfUse string `json:"purposeOfUse"`
		Subject      string `json:"subject"`
		Resources    struct {
			Path string `json:"path"`
		} `json:"resources"`
	}

	var subjectsQuery []credentialSubject
	if err := vcQuery.UnmarshalCredentialSubject(&subjectsQuery); err != nil {
		return core.InvalidInputError("failed to unmarshall VC subject: %w", err)
	}

	// convert to query
	query, err := w.VCR.Registry().QueryFor(concept.AuthorizationConcept)
	if err != nil {
		return err
	}
	if vcQuery.Issuer.String() != "" {
		query.AddClause(concept.Eq("issuer", vcQuery.Issuer.String()))
	}
	if len(subjectsQuery) > 0 {
		subjectQuery := subjectsQuery[0]
		if subjectQuery.ID != "" {
			query.AddClause(concept.Eq("credentialSubject.id", subjectQuery.ID))
		}
		if subjectQuery.PurposeOfUse != "" {
			query.AddClause(concept.Eq("credentialSubject.purposeOfUse", subjectQuery.PurposeOfUse))
		}
		if subjectQuery.Subject != "" {
			query.AddClause(concept.Eq("credentialSubject.subject", subjectQuery.Subject))
		}
		if subjectQuery.Resources.Path != "" {
			query.AddClause(concept.Eq("credentialSubject.resources.#.path", subjectQuery.Resources.Path))
		}
	}

	results, err := w.VCR.Search(ctx.Request().Context(), query, allowUntrusted, nil)
	if err != nil {
		return err
	}

	return ctx.JSON(http.StatusOK, results)
}

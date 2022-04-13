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
	"net/http"
	"sort"
	"strings"

	"github.com/labstack/echo/v4"
	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/jsonld"
	"github.com/nuts-foundation/nuts-node/vcr"
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

	reader := jsonld.Reader{DocumentLoader: w.ContextManager.DocumentLoader()}
	document, err := reader.Read(request.Query)
	if err != nil {
		return core.InvalidInputError("failed to convert query to JSON-LD expanded form: %w", err)
	}
	searchTerms := flatten(document, nil)
	searchTerms = filter(searchTerms)

	// sort terms to aid testing
	sort.Slice(searchTerms, func(i, j int) bool {
		left := strings.Join(searchTerms[i].IRIPath, "")
		right := strings.Join(searchTerms[j].IRIPath, "")

		return strings.Compare(left, right) < 0
	})

	results, err := w.VCR.Search(ctx.Request().Context(), searchTerms, untrusted, nil)
	if err != nil {
		return err
	}

	return ctx.JSON(http.StatusOK, results)
}

// filter default required values that are empty in the query
func filter(searchTerms []vcr.SearchTerm) []vcr.SearchTerm {
	i := 0
	for _, st := range searchTerms {
		switch value := st.Value.(type) {
		case string:
			if value != "" && value != "0001-01-01T00:00:00Z" {
				searchTerms[i] = st
				i++
			}
		case float64:
			if value != 0.0 {
				searchTerms[i] = st
				i++
			}
		}
		// TODO bool problem, luckily there are no default bool fields in a VC
	}
	return searchTerms[:i]
}

func flatten(document interface{}, currentPath []string) []vcr.SearchTerm {
	switch t := document.(type) {
	case jsonld.Document:
		return flattenSlice(t, currentPath)
	case []interface{}:
		return flattenSlice(t, currentPath)
	case map[string]interface{}:
		return flattenMap(t, currentPath)
	}

	return nil
}

func flattenSlice(expanded []interface{}, currentPath []string) []vcr.SearchTerm {
	result := make([]vcr.SearchTerm, 0)

	for _, sub := range expanded {
		result = append(result, flatten(sub, currentPath)...)
	}

	return result
}

func flattenMap(expanded map[string]interface{}, currentPath []string) []vcr.SearchTerm {
	// JSON-LD in expanded form either has @value, @id, @list or objects

	results := make([]vcr.SearchTerm, 0)

	for k, v := range expanded {
		switch k {
		case "@id":
			fallthrough
		case "@value":
			results = append(results, vcr.SearchTerm{
				IRIPath: currentPath,
				Value:   v,
			})
		case "@list":
			// TODO: not supported... This would require OR type queries
		default:
			results = append(results, flatten(v, append(currentPath, k))...)
		}
	}

	return results
}

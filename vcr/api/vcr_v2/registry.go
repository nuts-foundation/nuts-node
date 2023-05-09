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

package vcr_v2

import (
	"context"
	"encoding/json"
	"github.com/nuts-foundation/nuts-node/vcr/log"
	"github.com/sirupsen/logrus"
	"sort"
	"strings"

	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/jsonld"
	"github.com/nuts-foundation/nuts-node/vcr"
)

// ResolveVC handles the API request for resolving a VC
func (w *Wrapper) ResolveVC(ctx context.Context, request ResolveVCRequestObject) (ResolveVCResponseObject, error) {
	vcID, err := ssi.ParseURI(request.Id)
	if err != nil {
		return nil, core.InvalidInputError("invalid credential id: %w", err)
	}
	result, err := w.VCR.Resolve(*vcID, nil)
	if result != nil {
		// When err != nil credential is untrusted or revoked, credential is still returned.
		// This API call must return the VC regardless its status: https://github.com/nuts-foundation/nuts-node/issues/1221
		return ResolveVC200JSONResponse(*result), nil
	}
	return nil, err
}

// SearchVCs checks the context used in the JSON-LD query, based on the contents it maps to a non-JSON-LD query
// After V1, this needs to be remapped to a DB search that supports native JSON-LD
func (w *Wrapper) SearchVCs(ctx context.Context, request SearchVCsRequestObject) (SearchVCsResponseObject, error) {
	untrusted := false
	if request.Body.SearchOptions != nil && request.Body.SearchOptions.AllowUntrustedIssuer != nil {
		untrusted = *request.Body.SearchOptions.AllowUntrustedIssuer
	}

	if credentials, ok := request.Body.Query["credentialSubject"].([]interface{}); ok && len(credentials) > 1 {
		return nil, core.InvalidInputError("can't match on multiple VC subjects")
	}

	reader := jsonld.Reader{DocumentLoader: w.ContextManager.DocumentLoader()}
	document, err := reader.Read(request.Body.Query)
	if err != nil {
		return nil, core.InvalidInputError("failed to convert query to JSON-LD expanded form: %w", err)
	}

	if logrus.IsLevelEnabled(logrus.DebugLevel) {
		documentAsJson, _ := json.MarshalIndent(document, "", " ")
		log.Logger().Debugf("Expanded JSON-LD search query:\n%s", string(documentAsJson))
	}

	searchTerms := flatten(document, nil)

	// sort terms to aid testing
	sort.Slice(searchTerms, func(i, j int) bool {
		left := strings.Join(searchTerms[i].IRIPath, "")
		right := strings.Join(searchTerms[j].IRIPath, "")

		return strings.Compare(left, right) < 0
	})

	results, err := w.VCR.Search(ctx, searchTerms, untrusted, nil)
	if err != nil {
		return nil, err
	}
	searchResults, err := w.vcsWithRevocationsToSearchResults(results)
	if err != nil {
		return nil, err
	}
	return SearchVCs200JSONResponse(SearchVCResults{searchResults}), nil
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
			searchTerm := vcr.SearchTerm{
				IRIPath: currentPath,
				Value:   v,
			}
			// prefix matching for strings when it ends with an asterisk (*)
			if str, ok := v.(string); ok {
				if strings.HasSuffix(str, "*") {
					// search query with just * means: must be present, otherwise it's a prefix query
					if len(str) == 1 {
						searchTerm.Type = vcr.NotNil
						searchTerm.Value = nil
					} else {
						searchTerm.Type = vcr.Prefix
						searchTerm.Value = str[:len(str)-1]
					}
				}
			}
			results = append(results, searchTerm)
		case "@list":
			results = append(results, flatten(v, currentPath)...)
		default:
			results = append(results, flatten(v, append(currentPath, k))...)
		}
	}

	return results
}

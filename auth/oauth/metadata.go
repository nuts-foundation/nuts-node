/*
 * Copyright (C) 2026 Nuts community
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

package oauth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/nuts-foundation/nuts-node/core"
)

// FetchMetadata retrieves and validates a JSON metadata document of type T for identifier. The
// well-known path is taken from T.WellKnownPath(); the document is tried in both placements in
// priority order and the first candidate that returns 200, JSON-decodes into T, and whose
// GetIssuer() matches identifier (a trailing slash difference is tolerated, see identifiersMatch)
// is returned:
//
//  1. insert (RFC 8414):  https://host/.well-known/<wellKnown>/<path>
//  2. append (OIDC Disc): https://host/<path>/.well-known/<wellKnown>
//
// When identifier has no path, insert and append collapse to a single URL. Every candidate
// shares identifier's scheme and host, so the single core.ParsePublicURL SSRF check on
// identifier covers them all.
//
// When every candidate fails it returns, in order of preference: an upstream server error
// (core.HttpError with a 5xx status) as-is so callers can map it to 502; otherwise an error
// listing the non-404 failures; otherwise a plain "not found" error naming the identifier.
func FetchMetadata[T interface {
	WellKnownPath() string
	GetIssuer() string
}](ctx context.Context, httpClient core.HTTPRequestDoer, identifier string, strictMode bool) (*T, error) {
	var zero T
	candidates, err := wellKnownCandidates(identifier, strictMode, zero.WellKnownPath())
	if err != nil {
		return nil, err
	}
	// A 404 just means "not at this location" and is noise; only non-404 failures
	// (403/405/5xx, decode errors, identifier mismatch) are worth surfacing.
	var diagnostics []string
	for _, candidate := range candidates {
		metadata, status, fetchErr := fetchMetadataCandidate[T](ctx, httpClient, candidate, identifier)
		if fetchErr == nil {
			return metadata, nil
		}
		// Surface an upstream server error as-is (it is a core.HttpError carrying the
		// status) so callers serving an API can map it to 502 Bad Gateway.
		if status >= 500 {
			return nil, fetchErr
		}
		if status != http.StatusNotFound {
			diagnostics = append(diagnostics, fmt.Sprintf("%s: %v", candidate, fetchErr))
		}
	}
	if len(diagnostics) == 0 {
		return nil, fmt.Errorf("metadata not found at any candidate location for %q (tried: %s)", identifier, strings.Join(candidates, ", "))
	}
	return nil, fmt.Errorf("failed to retrieve metadata for %q: %s", identifier, strings.Join(diagnostics, "; "))
}

// fetchMetadataCandidate retrieves, JSON-decodes and validates the metadata document from a
// single candidate URL. It returns the HTTP status code (0 when no response was received) so the
// caller can distinguish a 404 from other failures and map upstream 5xx to 502.
func fetchMetadataCandidate[T interface{ GetIssuer() string }](ctx context.Context, httpClient core.HTTPRequestDoer, candidateURL string, identifier string) (*T, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, candidateURL, http.NoBody)
	if err != nil {
		return nil, 0, err
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	if httpErr := core.TestResponseCode(http.StatusOK, resp); httpErr != nil {
		return nil, resp.StatusCode, httpErr
	}
	var metadata T
	if err := json.NewDecoder(resp.Body).Decode(&metadata); err != nil {
		return nil, resp.StatusCode, fmt.Errorf("decoding metadata: %w", err)
	}
	// The issuer in the document MUST match the requested identifier, so a host cannot
	// steer discovery to metadata it serves under a different issuer. A mismatch falls
	// through to the next candidate.
	if !identifiersMatch(metadata.GetIssuer(), identifier) {
		return nil, resp.StatusCode, fmt.Errorf("issuer %q does not match requested identifier %q", metadata.GetIssuer(), identifier)
	}
	return &metadata, resp.StatusCode, nil
}

// identifiersMatch reports whether two issuer / credential-issuer identifiers are
// equal, tolerating a trailing-slash difference. RFC 8414 §3.3 and OpenID4VCI
// §12.2.4 require the identifier in a metadata document to be byte-identical to
// the requested identifier, but some servers (e.g. IdentityServer) normalize it
// with a trailing slash. Treat those as a match so discovery does not reject
// otherwise-valid metadata over a trailing slash.
func identifiersMatch(a string, b string) bool {
	return strings.TrimRight(a, "/") == strings.TrimRight(b, "/")
}

// wellKnownCandidates returns the metadata URLs to try for identifier, in priority order:
// the insert (RFC 8414) placement, then the append (OIDC Discovery) placement. When
// identifier has no path, both collapse to a single URL.
func wellKnownCandidates(identifier string, strictMode bool, wellKnown string) ([]string, error) {
	identifierURL, err := core.ParsePublicURL(identifier, strictMode)
	if err != nil {
		return nil, err
	}
	// insert places the well-known segment at the authority root with the identifier path
	// appended. RawPath is set alongside Path when present so url.String() does not re-escape
	// pre-encoded characters like %2F.
	insert := *identifierURL
	if strings.Trim(identifierURL.Path, "/") == "" {
		// No path: insert and append are identical; a single candidate suffices.
		insert.Path = wellKnown
		insert.RawPath = ""
		return []string{insert.String()}, nil
	}
	insert.Path = wellKnown + identifierURL.Path
	if identifierURL.RawPath != "" {
		insert.RawPath = wellKnown + identifierURL.RawPath
	}
	// append places the well-known segment after the identifier path (OIDC Discovery).
	appended := *identifierURL
	appended.Path = strings.TrimSuffix(identifierURL.Path, "/") + wellKnown
	if identifierURL.RawPath != "" {
		appended.RawPath = strings.TrimSuffix(identifierURL.RawPath, "/") + wellKnown
	}
	return []string{insert.String(), appended.String()}, nil
}

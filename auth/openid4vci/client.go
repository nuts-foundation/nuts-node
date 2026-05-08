/*
 * Nuts node
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
 */

package openid4vci

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/nuts-foundation/nuts-node/auth/oauth"
	"github.com/nuts-foundation/nuts-node/core"
)

// wellKnownPath is the path segment defined in OpenID4VCI 1.0 §12.2.2 for
// retrieving the Credential Issuer Metadata document.
const wellKnownPath = "/.well-known/openid-credential-issuer"

// RequestCredentialOpts carries all parameters for a Credential Request.
//
// CredentialIdentifier and CredentialConfigurationID are mutually exclusive
// per §8.2: when the Token Response carried authorization_details with
// credential_identifiers, the wallet MUST set CredentialIdentifier (and
// CredentialConfigurationID MUST NOT be present); otherwise the wallet sets
// CredentialConfigurationID. If both are non-empty, CredentialIdentifier
// takes precedence to enforce the spec rule.
type RequestCredentialOpts struct {
	CredentialEndpoint        string
	AccessToken               string
	CredentialConfigurationID string
	CredentialIdentifier      string
	ProofJWT                  string
}

// Client is the OpenID4VCI 1.0 HTTP client interface.
// It covers the three wire interactions a wallet makes against a Credential
// Issuer: fetching issuer metadata, obtaining a fresh nonce, and requesting
// a credential.
type Client interface {
	// OpenIDCredentialIssuerMetadata fetches and parses the Credential Issuer
	// Metadata document. The well-known URL is constructed from issuerURL per
	// RFC 8615 (well-known segment inserted at the authority root, with the
	// issuer path appended after).
	OpenIDCredentialIssuerMetadata(ctx context.Context, issuerURL string) (*OpenIDCredentialIssuerMetadata, error)

	// RequestNonce retrieves a fresh c_nonce from the Nonce Endpoint (§7.2).
	RequestNonce(ctx context.Context, nonceEndpoint string) (string, error)

	// RequestCredential posts a Credential Request (§8.2) and returns the
	// Credential Response (§8.3). On non-2xx the method returns a structured
	// Error when the body is a valid OpenID4VCI error object; otherwise a
	// generic error.
	RequestCredential(ctx context.Context, opts RequestCredentialOpts) (*CredentialResponse, error)
}

// NewClient returns a Client backed by the provided HTTP request doer.
// In production callers should pass *httpclient.StrictHTTPClient so the
// shared transport policies apply (HTTPS-in-strict, body size limit,
// User-Agent header).
//
// When strictMode is true, target URLs are additionally validated via
// core.ParsePublicURL: HTTPS scheme, no IP hosts, no reserved hostnames.
func NewClient(httpClient core.HTTPRequestDoer, strictMode bool) Client {
	return &client{httpClient: httpClient, strictMode: strictMode}
}

type client struct {
	httpClient core.HTTPRequestDoer
	strictMode bool
}

// validateURL guards against SSRF by rejecting target URLs that fail
// core.ParsePublicURL (in strict mode: HTTPS only, no IP/reserved hosts).
// Called at the entry of every method that makes outbound HTTP.
//
// TODO: this validation belongs on httpclient.StrictHTTPClient so every
// outbound HTTP call (not just OpenID4VCI) gets the IP/reserved-host check,
// not only the HTTPS scheme check that StrictHTTPClient.Do enforces today.
// Placed here for now to preserve parity with master, where the equivalent
// caller (auth/client/iam.HTTPClient) validated via oauth.IssuerIdToWellKnown
// → core.ParsePublicURL before issuing the request, and to address a CodeQL
// SSRF finding on this PR. Tracked as a follow-up to consolidate the check
// in the shared HTTP client.
func (c *client) validateURL(name, target string) error {
	if _, err := core.ParsePublicURL(target, c.strictMode); err != nil {
		return fmt.Errorf("openid4vci: invalid %s URL: %w", name, err)
	}
	return nil
}

func (c *client) OpenIDCredentialIssuerMetadata(ctx context.Context, issuerURL string) (*OpenIDCredentialIssuerMetadata, error) {
	if err := c.validateURL("issuer", issuerURL); err != nil {
		return nil, err
	}
	// Per §12.2.1, the Credential Issuer Identifier MUST NOT contain query
	// or fragment components.
	if parsed, _ := url.Parse(issuerURL); parsed != nil && (parsed.RawQuery != "" || parsed.Fragment != "") {
		return nil, fmt.Errorf("openid4vci: invalid issuer URL: query and fragment components are not allowed")
	}
	wellKnownURL, err := credentialIssuerWellKnown(issuerURL)
	if err != nil {
		return nil, fmt.Errorf("openid4vci: invalid issuer URL: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, wellKnownURL, http.NoBody)
	if err != nil {
		return nil, err
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, fmt.Errorf("openid4vci: fetching issuer metadata returned status %d", resp.StatusCode)
	}
	var metadata OpenIDCredentialIssuerMetadata
	if err := json.NewDecoder(resp.Body).Decode(&metadata); err != nil {
		return nil, fmt.Errorf("openid4vci: decoding issuer metadata: %w", err)
	}
	// Per §12.2.4: the credential_issuer value MUST match the issuer identifier
	// the metadata document was retrieved for. Mismatched metadata MUST NOT be used.
	if metadata.CredentialIssuer != issuerURL {
		return nil, fmt.Errorf("openid4vci: credential_issuer %q does not match requested issuer %q", metadata.CredentialIssuer, issuerURL)
	}
	return &metadata, nil
}

func (c *client) RequestNonce(ctx context.Context, nonceEndpoint string) (string, error) {
	if err := c.validateURL("nonce endpoint", nonceEndpoint); err != nil {
		return "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, nonceEndpoint, http.NoBody)
	if err != nil {
		return "", err
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return "", fmt.Errorf("openid4vci: nonce endpoint returned status %d", resp.StatusCode)
	}
	var nonceResp NonceResponse
	if err := json.NewDecoder(resp.Body).Decode(&nonceResp); err != nil {
		return "", fmt.Errorf("openid4vci: decoding nonce response: %w", err)
	}
	if nonceResp.CNonce == "" {
		return "", fmt.Errorf("openid4vci: nonce endpoint returned empty c_nonce")
	}
	return nonceResp.CNonce, nil
}

func (c *client) RequestCredential(ctx context.Context, opts RequestCredentialOpts) (*CredentialResponse, error) {
	if err := c.validateURL("credential endpoint", opts.CredentialEndpoint); err != nil {
		return nil, err
	}
	body := CredentialRequest{
		Proofs: &CredentialRequestProofs{
			JWT: []string{opts.ProofJWT},
		},
	}
	// Per §8.2: CredentialIdentifier and CredentialConfigurationID are mutually
	// exclusive. CredentialIdentifier wins when set.
	if opts.CredentialIdentifier != "" {
		body.CredentialIdentifier = opts.CredentialIdentifier
	} else {
		body.CredentialConfigurationID = opts.CredentialConfigurationID
	}
	bodyBytes, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, opts.CredentialEndpoint, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+opts.AccessToken)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// Buffer the body once so the non-2xx path can attempt structured-error
	// parsing before falling back to a generic error.
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		var oauthErr oauth.OAuth2Error
		if jsonErr := json.Unmarshal(respBody, &oauthErr); jsonErr == nil && oauthErr.Code != "" {
			return nil, oauthErr
		}
		return nil, fmt.Errorf("openid4vci: credential endpoint returned status %d", resp.StatusCode)
	}
	var credResp CredentialResponse
	if err := json.Unmarshal(respBody, &credResp); err != nil {
		return nil, fmt.Errorf("openid4vci: decoding credential response: %w", err)
	}
	return &credResp, nil
}

// credentialIssuerWellKnown returns the Credential Issuer Metadata URL for
// the given issuer identifier per RFC 8615: the well-known segment is
// inserted at the authority root, and the issuer's path is appended after.
//
// Example: https://example.com/oauth2/alice
//   ->     https://example.com/.well-known/openid-credential-issuer/oauth2/alice
func credentialIssuerWellKnown(issuerURL string) (string, error) {
	u, err := url.Parse(issuerURL)
	if err != nil {
		return "", err
	}
	// Prepend the well-known segment to both Path (decoded) and RawPath
	// (encoded) when the latter is set, so u.String() does not double-escape
	// pre-encoded characters like %2F via EscapedPath's reescaping pass.
	u.Path = wellKnownPath + u.Path
	if u.RawPath != "" {
		u.RawPath = wellKnownPath + u.RawPath
	}
	return u.String(), nil
}

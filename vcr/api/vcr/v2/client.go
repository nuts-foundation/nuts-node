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
	"context"
	"encoding/json"
	"fmt"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/core"
	"io"
	"net/http"
)

// HTTPClient holds the server address and other basic settings for the http client
type HTTPClient struct {
	core.ClientConfig
	TokenGenerator core.AuthorizationTokenGenerator
}

func (hb HTTPClient) client() ClientInterface {
	response, err := NewClientWithResponses(hb.GetAddress(), WithHTTPClient(core.MustCreateHTTPClient(hb.ClientConfig, hb.TokenGenerator)))
	if err != nil {
		panic(err)
	}
	return response
}

// Trust sends a request to the node to trust a specific issuer for a credential type
func (hb HTTPClient) Trust(credentialType string, issuer string) error {
	ctx := context.Background()

	body := TrustIssuerJSONRequestBody{
		CredentialType: credentialType,
		Issuer:         issuer,
	}

	response, err := hb.client().TrustIssuer(ctx, body)
	if err != nil {
		return err
	}

	return core.TestResponseCode(http.StatusNoContent, response)
}

// Untrust sends a request to the node to untrust a specific issuer for a credential type
func (hb HTTPClient) Untrust(credentialType string, issuer string) error {
	ctx := context.Background()

	body := UntrustIssuerJSONRequestBody{
		CredentialType: credentialType,
		Issuer:         issuer,
	}

	response, err := hb.client().UntrustIssuer(ctx, body)
	if err != nil {
		return err
	}

	return core.TestResponseCode(http.StatusNoContent, response)
}

// Trusted lists the trusted issuers for the given credential type
func (hb HTTPClient) Trusted(credentialType string) ([]string, error) {
	ctx := context.Background()

	return handleTrustedResponse(hb.client().ListTrusted(ctx, credentialType))
}

// Untrusted lists the untrusted issuers for the given credential type
func (hb HTTPClient) Untrusted(credentialType string) ([]string, error) {
	ctx := context.Background()

	return handleTrustedResponse(hb.client().ListUntrusted(ctx, credentialType))
}

// LoadVC loads the given Verifiable Credential into the holder's wallet.
func (hb HTTPClient) LoadVC(holder did.DID, credential vc.VerifiableCredential) error {
	ctx := context.Background()

	httpResponse, err := hb.client().LoadVC(ctx, holder.String(), credential)
	if err != nil {
		return err
	} else if err := core.TestResponseCode(http.StatusNoContent, httpResponse); err != nil {
		return err
	}
	return nil
}

// IssueVC issues a new Verifiable Credential and returns it
func (hb HTTPClient) IssueVC(request IssueVCRequest) (*VerifiableCredential, error) {
	ctx := context.Background()

	httpResponse, err := hb.client().IssueVC(ctx, request)
	if err != nil {
		return nil, err
	} else if err := core.TestResponseCode(http.StatusOK, httpResponse); err != nil {
		return nil, err
	}

	response, err := ParseIssueVCResponse(httpResponse)
	if err != nil {
		return nil, err
	}
	return response.JSON200, err
}

func handleTrustedResponse(response *http.Response, err error) ([]string, error) {
	if err != nil {
		return nil, err
	} else if err := core.TestResponseCode(http.StatusOK, response); err != nil {
		return nil, err
	} else {
		return readIssuers(response.Body)
	}
}

func readIssuers(reader io.Reader) ([]string, error) {
	var data []byte
	var err error

	if data, err = io.ReadAll(reader); err != nil {
		return nil, fmt.Errorf("unable to read response: %w", err)
	}
	issuers := make([]string, 0)
	if err = json.Unmarshal(data, &issuers); err != nil {
		return nil, fmt.Errorf("unable to unmarshal response: %w, %s", err, string(data))
	}
	return issuers, nil
}

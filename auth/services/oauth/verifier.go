/*
 * Nuts node
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

package oauth

import (
	"context"
	"crypto/tls"
	"fmt"
	"github.com/nuts-foundation/nuts-node/auth/client/iam"
	"github.com/nuts-foundation/nuts-node/vdr/didweb"
	"net/url"
	"time"

	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/auth/oauth"
)

var _ Verifier = (*VerifierServiceProvider)(nil)

type VerifierServiceProvider struct {
	strictMode        bool
	httpClientTimeout time.Duration
	httpClientTLS     *tls.Config
}

// NewVerifier returns an implementation of Verifier
func NewVerifier(strictMode bool, httpClientTimeout time.Duration, httpClientTLS *tls.Config) *VerifierServiceProvider {
	return &VerifierServiceProvider{
		strictMode:        strictMode,
		httpClientTimeout: httpClientTimeout,
		httpClientTLS:     httpClientTLS,
	}
}

func (v *VerifierServiceProvider) AuthorizationServerMetadata(ctx context.Context, webdid did.DID) (*oauth.AuthorizationServerMetadata, error) {
	iamClient := iam.NewHTTPClient(v.strictMode, v.httpClientTimeout, v.httpClientTLS)
	// the wallet/holder acts as authorization server
	metadata, err := iamClient.OAuthAuthorizationServerMetadata(ctx, webdid)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve remote OAuth Authorization Server metadata: %w", err)
	}
	return metadata, nil
}

func (v *VerifierServiceProvider) ClientMetadataURL(webdid did.DID) (*url.URL, error) {
	didURL, err := didweb.DIDToURL(webdid)
	if err != nil {
		return nil, fmt.Errorf("failed to convert DID to URL: %w", err)
	}
	// we use the authorization server endpoint as the client metadata endpoint, contents are the same
	// coming from a did:web, it's impossible to get a false URL
	return didURL.JoinPath(oauth.ClientMetadataPath), nil
}

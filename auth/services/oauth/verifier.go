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
	"crypto/tls"
	"fmt"
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

func (v *VerifierServiceProvider) ClientMetadataURL(webdid did.DID) (*url.URL, error) {
	didURL, err := didweb.DIDToURL(webdid)
	if err != nil {
		return nil, fmt.Errorf("failed to convert DID to URL: %w", err)
	}
	// we use the authorization server endpoint as the client metadata endpoint, contents are the same
	// coming from a did:web, it's impossible to get a false URL
	metadataURL, _ := oauth.IssuerIdToWellKnown(didURL.String(), oauth.AuthzServerWellKnown, v.strictMode)
	return metadataURL, nil
}

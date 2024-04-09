/*
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

package iam

import (
	"errors"
	"fmt"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/http"
	"github.com/nuts-foundation/nuts-node/vcr/pe"
	"net/url"
)

// OAuthSession is the session object that is used to store information about the OAuth request.
// The client state (and nonce/redirectToken as well) is used to refer to this session.
// Both the client and the server use this session to store information about the request.
type OAuthSession struct {
	ClientID               string
	Scope                  string
	OwnDID                 *did.DID
	ClientState            string
	SessionID              string
	RedirectURI            string
	ServerState            ServerState
	ResponseType           string
	PresentationDefinition PresentationDefinition
	VerifierDID            *did.DID

	// TODO use these 2 fields to track if all OpenID4VP flows have been concluded
	// PresentationSubmissions tracks which PresentationSubmissions have been submitted through OpenID4VP
	PresentationSubmissions map[string]pe.PresentationSubmission
	// Presentations tracks which VerifiablePresentations have been received through OpenID4VP
	Presentations map[string]vc.VerifiablePresentation
}

// UserSession is a session-bound Verifiable Credential wallet.
type UserSession struct {
	// TenantDID is the requesting DID when the user session was created, typically the employer's (of the user) DID.
	// A session needs to be scoped to the tenant DID, since the session gives access to the tenant's wallet,
	// and the user session might contain session-bound credentials (e.g. EmployeeCredential) that were issued by the tenant.
	TenantDID did.DID `json:"tenantDID"`
	// PreAuthorizedUser is the user that is pre-authorized by the client application.
	// It is stored to later assert that subsequent RequestUserAccessToken() calls that (accidentally or intentionally)
	// re-use the browser session, are indeed for the same client application user.
	PreAuthorizedUser *UserDetails `json:"preauthorized_user"`
	Wallet            UserWallet   `json:"wallet"`
}

// UserWallet is a session-bound Verifiable Credential wallet.
// It's an in-memory wallet which contains the user's private key in plain text.
// This is OK, since the associated credentials are intended for protocol compatibility (OpenID4VP with a low-assurance EmployeeCredential),
// when an actual user wallet is involved, this wallet isn't used.
type UserWallet struct {
	Credentials []vc.VerifiableCredential
	// JWK is an in-memory key pair associated with the user's wallet in JWK form.
	JWK []byte
	// DID is the did:jwk DID of the user's wallet.
	DID did.DID
}

// Key returns the JWK as jwk.Key
func (w UserWallet) Key() (jwk.Key, error) {
	set, err := jwk.Parse(w.JWK)
	if err != nil {
		return nil, fmt.Errorf("failed to parse JWK: %w", err)
	}
	result, available := set.Key(0)
	if !available {
		return nil, errors.New("expected exactly 1 key in the JWK set")
	}
	return result, nil
}

// ServerState is a convenience type for extracting different types of data from the session.
type ServerState struct {
	CredentialMap          map[string]vc.VerifiableCredential
	Presentations          []vc.VerifiablePresentation
	PresentationSubmission *pe.PresentationSubmission
}

// RedirectSession is the session object that is used to redirect the user to a Nuts node website.
// It stores information from the internal API call that started the request access token.
// The key to this session is passed to the user via a 302 redirect.
type RedirectSession struct {
	AccessTokenRequest RequestUserAccessTokenRequestObject
	// SessionID is used by the calling app to get the access token later on
	SessionID string
	OwnDID    did.DID
}

func (s OAuthSession) CreateRedirectURI(params map[string]string) string {
	redirectURI, _ := url.Parse(s.RedirectURI)
	r := http.AddQueryParams(*redirectURI, params)
	return r.String()
}

func (s OAuthSession) redirectURI() *url.URL {
	redirectURL, _ := url.Parse(s.RedirectURI)
	return redirectURL
}

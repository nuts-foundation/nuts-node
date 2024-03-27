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
}

// UserSession is a session-bound Verifiable Credential wallet.
type UserSession struct {
	// TenantDID is the requesting DID when the user session was created, typically the employer's (of the user) DID.
	// A session needs to be scoped to the tenant DID, since the session gives access to the tenant's wallet,
	// and the user session might contain session-bound credentials (e.g. EmployeeCredential) that were issued by the tenant.
	TenantDID did.DID    `json:"tenantDID"`
	Wallet    UserWallet `json:"wallet"`
}

// UserWallet is a session-bound Verifiable Credential wallet.
type UserWallet struct {
	Credentials []vc.VerifiableCredential
	// JWK is an in-memory key pair associated with the user's wallet in JWK form.
	JWK []byte
}

// ServerState is a convenience type for extracting different types of data from the session.
type ServerState map[string]interface{}

const (
	credentialMapStateKey = "credentialMap"
	presentationsStateKey = "presentations"
	submissionStateKey    = "presentationSubmission"
)

// VerifiablePresentations returns the verifiable presentations from the server state.
// If the server state does not contain a verifiable presentation, an empty slice is returned.
func (s ServerState) VerifiablePresentations() []vc.VerifiablePresentation {
	presentations := make([]vc.VerifiablePresentation, 0)
	if val, ok := s[presentationsStateKey]; ok {
		// each entry should be castable to a VerifiablePresentation
		if arr, ok := val.([]interface{}); ok {
			for _, v := range arr {
				if vp, ok := v.(vc.VerifiablePresentation); ok {
					presentations = append(presentations, vp)
				}
			}
		}
	}
	return presentations
}

// PresentationSubmission returns the Presentation Submission from the server state.
func (s ServerState) PresentationSubmission() *pe.PresentationSubmission {
	if val, ok := s[submissionStateKey].(pe.PresentationSubmission); ok {
		return &val
	}
	return nil
}

// CredentialMap returns the credential map from the server state.
func (s ServerState) CredentialMap() map[string]vc.VerifiableCredential {
	if mapped, ok := s[credentialMapStateKey].(map[string]vc.VerifiableCredential); ok {
		return mapped
	}
	return map[string]vc.VerifiableCredential{}
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

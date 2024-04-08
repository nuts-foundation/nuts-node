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
	UserDetails            UserDetails
	VerifierDID            *did.DID

	// TODO use these 2 fields to track if all OpenID4VP flows have been concluded
	// PresentationSubmissions tracks which PresentationSubmissions have been submitted through OpenID4VP
	PresentationSubmissions map[string]pe.PresentationSubmission
	// Presentations tracks which VerifiablePresentations have been received through OpenID4VP
	Presentations map[string]vc.VerifiablePresentation
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

// The Oid4vciSession is used to hold the state of an OIDC4VCi request between the moment
// the client application does the request, the OIDC4VCi flow and the redirect back to the
// client. The Oid4vciSession is referred to by a generated session id shared with the downstream
// OIDC4VCi issuer.
type Oid4vciSession struct {
	// HolderDid: the DID of the wallet holder to who the VC will be issued to.
	HolderDid *did.DID
	// IssuerDid: the DID of the VC issuer, the party that will issue the VC to the holders' wallet
	IssuerDid *did.DID
	// RemoteRedirectUri: The redirect URL as provided by the external application requesting the issuance.
	RemoteRedirectUri string
	// RedirectUri: the URL send to the issuer as the redirect_uri of this nuts-node.
	RedirectUri string
	// PKCEParams: a set of Proof Key for Code Exchange parameters generated for this request.
	PKCEParams PKCEParams
	// IssuerTokenEndpoint: the endpoint for fetching the access token of the issuer.
	IssuerTokenEndpoint string
	// IssuerCredentialEndpoint: the endpoint for fetching the credential from the issuer with
	// the access_token fetched from the IssuerTokenEndpoint.
	IssuerCredentialEndpoint string
}

// The remoteRedirectUri returns the RemoteRedirectUri as pared URL reference.
func (s Oid4vciSession) remoteRedirectUri() *url.URL {
	redirectURL, _ := url.Parse(s.RemoteRedirectUri)
	return redirectURL
}

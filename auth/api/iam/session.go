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
	ResponseType           string
	PKCEParams             PKCEParams
	PresentationDefinition PresentationDefinition
	VerifierDID            *did.DID
	OpenID4VPVerifier      *OpenID4VPVerifier
}

// OpenID4VPVerifier tracks the verifier's state of multiple OpenID4VP flows that all relate to a single OAuthSession (e.g. Authorization Code flow).
type OpenID4VPVerifier struct {
	WalletDID                       did.DID
	RequiredPresentationDefinitions pe.WalletOwnerMapping
	// Submissions tracks which Submissions have been submitted through OpenID4VP
	Submissions map[string]pe.PresentationSubmission
	// Presentations tracks which VerifiablePresentations have been received through OpenID4VP
	Presentations []vc.VerifiablePresentation
	// Credentials maps the Presentation Definition Input Descriptor ID to the Verifiable Credential that was used to fulfill it.
	// The fields in these credentials are used to create the access token later on.
	Credentials map[string]vc.VerifiableCredential
}

// next returns the Presentation Definition that should be fulfilled next.
// It also returns the wallet owner type that should fulfill the Presentation Definition.
// If all Presentation Definitions have been fulfilled, it returns nil.
func (v *OpenID4VPVerifier) next() (*pe.WalletOwnerType, *pe.PresentationDefinition) {
	// Note: this is now fairly hardcoded, since there are only 2 PDs possible, one targeting the organization wallet and
	//       1 targeting the user wallet. In the future, this could be more dynamic.
	if def, required := v.RequiredPresentationDefinitions[pe.WalletOwnerOrganization]; required && !v.isFulfilled(def.Id) {
		org := pe.WalletOwnerOrganization
		return &org, &def
	}
	if def, required := v.RequiredPresentationDefinitions[pe.WalletOwnerUser]; required && !v.isFulfilled(def.Id) {
		user := pe.WalletOwnerUser
		return &user, &def
	}
	return nil, nil
}

// fulfill tries to fulfill the given Presentation Definition with the given submission and presentations.
// It returns an error if the Presentation Definition (identified by ID) isn't required, or already is fulfilled.
// It does not check whether the submission actually matches the Presentation Definition, that's the caller's responsibility.
func (v *OpenID4VPVerifier) fulfill(definitionID string, submission pe.PresentationSubmission, presentations []vc.VerifiablePresentation, credentials map[string]vc.VerifiableCredential) error {
	// Make sure this definition is actually required
	required := false
	for _, curr := range v.RequiredPresentationDefinitions {
		if curr.Id == definitionID {
			required = true
			break
		}
	}
	if !required {
		return fmt.Errorf("presentation definition being fulfilled is not required: %s", definitionID)
	}
	// Make sure this definition isn't already fulfilled
	if v.isFulfilled(definitionID) {
		return errors.New("presentation definition is already fulfilled")
	}
	// Store
	v.Submissions[definitionID] = submission
	v.Presentations = append(v.Presentations, presentations...)
	// Store the credentials
	for id, cred := range credentials {
		v.Credentials[id] = cred
	}
	return nil
}

func (v *OpenID4VPVerifier) isFulfilled(presentationDefinitionID string) bool {
	_, fulfilled := v.Submissions[presentationDefinitionID]
	return fulfilled
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

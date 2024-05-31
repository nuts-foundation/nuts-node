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
	"net/url"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/http"
	"github.com/nuts-foundation/nuts-node/vcr/pe"
)

// OAuthSession is the session object that is used to store information about the OAuth request.
// The client state (and nonce/redirectToken as well) is used to refer to this session.
// Both the client and the server use this session to store information about the request.
type OAuthSession struct {
	ClientFlow        oauthClientFlow `json:"client_flow,omitempty"`
	ClientID          string          `json:"client_id,omitempty"`
	ClientState       string          `json:"client_state,omitempty"`
	OpenID4VPVerifier *PEXConsumer    `json:"openid4vp_verifier,omitempty"`
	OwnDID            *did.DID        `json:"own_did,omitempty"`
	OtherDID          *did.DID        `json:"other_did,omitempty"`
	PKCEParams        PKCEParams      `json:"pkce_params"`
	RedirectURI       string          `json:"redirect_uri,omitempty"`
	Scope             string          `json:"scope,omitempty"`
	SessionID         string          `json:"session_id,omitempty"`
	TokenEndpoint     string          `json:"token_endpoint,omitempty"`
	UseDPoP           bool            `json:"use_dpop,omitempty"`
	// IssuerCredentialEndpoint: endpoint to exchange the access_token for a credential in the OpenID4VCI flow
	IssuerCredentialEndpoint string `json:"issuer_credential_endpoint,omitempty"`
}

// oauthClientFlow is used by a client to identify the flow a particular callback is part of
type oauthClientFlow = string

const (
	// accessTokenRequestClientFlow is used in the standard authorization_code flow to request an access_token
	accessTokenRequestClientFlow oauthClientFlow = "access_token_request"
	// credentialRequestClientFlow is used in the OpenID4VCI Credential Request flow
	credentialRequestClientFlow oauthClientFlow = "openid4vci_credential_request"
)

// PEXConsumer consumes Presentation Submissions, according to https://identity.foundation/presentation-exchange/
// This is a component of a OpenID4VP Verifier.
// It can track multiple required Presentation Definitions.
type PEXConsumer struct {
	RequiredPresentationDefinitions pe.WalletOwnerMapping `json:"required_presentations"`
	// Submissions tracks which Submissions have been submitted through OpenID4VP
	Submissions map[string]pe.PresentationSubmission `json:"submissions"`
	// SubmittedEnvelopes tracks the Presentation Exchange Envelopes that were submitted.
	// They correspond to the submissions.
	SubmittedEnvelopes map[string]pe.Envelope `json:"submitted_envelopes"`
}

func newPEXConsumer(requiredPresentationDefinitions pe.WalletOwnerMapping) *PEXConsumer {
	return &PEXConsumer{
		RequiredPresentationDefinitions: requiredPresentationDefinitions,
		Submissions:                     map[string]pe.PresentationSubmission{},
		SubmittedEnvelopes:              map[string]pe.Envelope{},
	}
}

// next returns the Presentation Definition that should be fulfilled next.
// It also returns the wallet owner type that should fulfill the Presentation Definition.
// If all Presentation Definitions have been fulfilled, it returns nil.
func (v *PEXConsumer) next() (*pe.WalletOwnerType, *pe.PresentationDefinition) {
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

// fulfill tries to fulfill the given Presentation Definition with the given submission and PEX envelope.
// It returns an error if the Presentation Definition (identified by ID) isn't required, or already is fulfilled.
// It does not check whether the submission actually matches the Presentation Definition, that's the caller's responsibility.
func (v *PEXConsumer) fulfill(submission pe.PresentationSubmission, envelope pe.Envelope) error {
	definitionID := submission.DefinitionId
	// Make sure this definition is actually required
	var definition *PresentationDefinition
	for _, curr := range v.RequiredPresentationDefinitions {
		if curr.Id == definitionID {
			definition = &curr
			break
		}
	}
	if definition == nil {
		return fmt.Errorf("presentation definition being fulfilled is not required: %s", definitionID)
	}
	// Make sure this definition isn't already fulfilled
	if v.isFulfilled(definitionID) {
		return errors.New("presentation definition is already fulfilled")
	}

	_, err := submission.Validate(envelope, *definition)
	if err != nil {
		return fmt.Errorf("presentation submission does not conform to presentation definition (id=%s)", definition.Id)
	}

	v.Submissions[definitionID] = submission
	v.SubmittedEnvelopes[definitionID] = envelope
	return nil
}

func (v *PEXConsumer) isFulfilled(presentationDefinitionID string) bool {
	_, fulfilled := v.Submissions[presentationDefinitionID]
	return fulfilled
}

// credentialMap returns a map of input descriptor ID to Verifiable Credential.
func (v *PEXConsumer) credentialMap() (map[string]vc.VerifiableCredential, error) {
	credentialMap := make(map[string]vc.VerifiableCredential)
	for _, requiredDefinition := range v.RequiredPresentationDefinitions {
		submission := v.Submissions[requiredDefinition.Id]
		pexEnvelope := v.SubmittedEnvelopes[requiredDefinition.Id]
		currCredentialMap, err := submission.Resolve(pexEnvelope)
		if err != nil {
			return nil, err
		}
		for inputDescriptorID, cred := range currCredentialMap {
			credentialMap[inputDescriptorID] = cred
		}
	}
	return credentialMap, nil
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

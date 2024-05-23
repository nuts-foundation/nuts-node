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

	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/http"
	"github.com/nuts-foundation/nuts-node/vcr/pe"
)

// OAuthSession is the session object that is used to store information about the OAuth request.
// The client state (and nonce/redirectToken as well) is used to refer to this session.
// Both the client and the server use this session to store information about the request.
type OAuthSession struct {
	ClientID          string       `json:"client_id,omitempty"`
	ClientState       string       `json:"client_state,omitempty"`
	OpenID4VPVerifier *PEXConsumer `json:"openid4vp_verifier,omitempty"`
	OwnDID            *did.DID     `json:"own_did,omitempty"`
	PKCEParams        PKCEParams   `json:"pkce_params"`
	RedirectURI       string       `json:"redirect_uri,omitempty"`
	ResponseType      string       `json:"response_type,omitempty"`
	Scope             string       `json:"scope,omitempty"`
	SessionID         string       `json:"session_id,omitempty"`
	TokenEndpoint     string       `json:"token_endpoint,omitempty"`
	UseDPoP           bool         `json:"use_dpop,omitempty"`
	VerifierDID       *did.DID     `json:"verifier_did,omitempty"`
}

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

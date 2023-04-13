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

package issuer

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/audit"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/vcr/log"
	"github.com/nuts-foundation/nuts-node/vcr/oidc4vci"
	"net/http"
	"net/url"
	"sync"
)

// ErrUnknownIssuer is returned when the given issuer is unknown.
var ErrUnknownIssuer = errors.New("unknown OIDC4VCI issuer")

var _ OIDCIssuer = (*memoryIssuer)(nil)

// OIDCIssuer defines the interface for an OIDC4VCI credential issuer. It is multi-tenant, accompanying the system
// managing an arbitrary number of actual issuers.
type OIDCIssuer interface {
	// ProviderMetadata returns the OpenID Connect provider metadata for the given issuer.
	ProviderMetadata(issuer did.DID) (oidc4vci.ProviderMetadata, error)
	// RequestAccessToken requests an OAuth2 access token for the given issuer and pre-authorized code.
	RequestAccessToken(ctx context.Context, issuer did.DID, preAuthorizedCode string) (string, error)
	// Metadata returns the OIDC4VCI credential issuer metadata for the given issuer.
	Metadata(issuer did.DID) (oidc4vci.CredentialIssuerMetadata, error)
	// Offer sends a credential offer to the specified wallet. It derives the issuer from the credential.
	Offer(ctx context.Context, credential vc.VerifiableCredential, walletURL string) error
	// RequestCredential requests a credential from the given issuer.
	RequestCredential(ctx context.Context, issuer did.DID, accessToken string) (vc.VerifiableCredential, error)
}

// NewOIDCIssuer creates a new Issuer instance. The identifier is the Credential Issuer Identifier, e.g. https://example.com/issuer/
func NewOIDCIssuer(baseURL string) OIDCIssuer {
	return &memoryIssuer{
		baseURL:      baseURL,
		state:        make(map[string]vc.VerifiableCredential),
		accessTokens: make(map[string]string),
		mux:          &sync.Mutex{},
	}
}

type memoryIssuer struct {
	baseURL string
	// state maps a pre-authorized code to a Verifiable Credential
	state map[string]vc.VerifiableCredential
	// accessToken maps an access token to a pre-authorized code
	accessTokens map[string]string
	mux          *sync.Mutex
}

func (i *memoryIssuer) Metadata(issuer did.DID) (oidc4vci.CredentialIssuerMetadata, error) {
	// TODO: Check if issuer is served by this instance
	//       See https://github.com/nuts-foundation/nuts-node/issues/2054
	return oidc4vci.CredentialIssuerMetadata{
		CredentialIssuer:     i.getIdentifier(issuer.String()),
		CredentialEndpoint:   i.getIdentifier(issuer.String()) + "/issuer/oidc4vci/credential",
		CredentialsSupported: []map[string]interface{}{{"NutsAuthorizationCredential": map[string]interface{}{}}},
	}, nil
}

func (i *memoryIssuer) ProviderMetadata(issuer did.DID) (oidc4vci.ProviderMetadata, error) {
	// TODO: Check if issuer is served by this instance
	//       See https://github.com/nuts-foundation/nuts-node/issues/2054
	return oidc4vci.ProviderMetadata{
		Issuer:        i.getIdentifier(issuer.String()),
		TokenEndpoint: i.getIdentifier(issuer.String()) + "/oidc/token",
	}, nil
}

func (i *memoryIssuer) RequestAccessToken(ctx context.Context, issuer did.DID, preAuthorizedCode string) (string, error) {
	// TODO: Check if issuer is served by this instance
	//       See https://github.com/nuts-foundation/nuts-node/issues/2054
	i.mux.Lock()
	defer i.mux.Unlock()
	_, ok := i.state[preAuthorizedCode]
	if !ok {
		audit.Log(ctx, log.Logger(), audit.InvalidOAuthTokenEvent).
			Info("Client tried requesting access token (for OIDC4VCI) with unknown OAuth2 pre-authorized code")
		return "", errors.New("unknown pre-authorized code")
	}
	accessToken := generateCode()
	i.accessTokens[accessToken] = preAuthorizedCode
	return accessToken, nil
}

func (i *memoryIssuer) Offer(ctx context.Context, credential vc.VerifiableCredential, clientMetadataURL string) error {
	// TODO: Check if issuer is served by this instance
	//       See https://github.com/nuts-foundation/nuts-node/issues/2054
	i.mux.Lock()
	preAuthorizedCode := generateCode()
	i.state[preAuthorizedCode] = credential
	i.mux.Unlock()

	subject, err := getSubjectDID(credential)
	if err != nil {
		return err
	}
	log.Logger().Infof("Publishing credential for subject %s using OIDC4VCI", subject)

	// TODO: Support TLS
	//       See https://github.com/nuts-foundation/nuts-node/issues/2032
	client, err := oidc4vci.NewWalletAPIClient(ctx, &http.Client{}, clientMetadataURL)
	if err != nil {
		return err
	}

	offer := oidc4vci.CredentialOffer{
		CredentialIssuer: i.getIdentifier(credential.Issuer.String()),
		Credentials: []map[string]interface{}{{
			"format": "VerifiableCredentialJSONLDFormat",
			"credential_definition": map[string]interface{}{
				"@context": credential.Context,
				"types":    credential.Type,
			},
		}},
		Grants: []map[string]interface{}{
			{
				oidc4vci.PreAuthorizedCodeGrant: map[string]interface{}{
					"pre-authorized_code": preAuthorizedCode,
				},
			},
		},
	}

	err = client.HandleCredentialOffer(ctx, offer)
	if err != nil {
		return fmt.Errorf("unable to offer credential (url=%s): %w", client.Metadata().CredentialOfferEndpoint, err)
	}
	return nil
}

func (i *memoryIssuer) RequestCredential(ctx context.Context, issuer did.DID, accessToken string) (vc.VerifiableCredential, error) {
	// TODO: Check if issuer is served by this instance
	//       See https://github.com/nuts-foundation/nuts-node/issues/2054
	i.mux.Lock()
	defer i.mux.Unlock()
	// TODO: Verify requested format and credential definition
	//       See https://github.com/nuts-foundation/nuts-node/issues/2037
	// TODO: Verify Proof-of-Possession of private key material
	//       See https://github.com/nuts-foundation/nuts-node/issues/2036
	preAuthorizedCode, ok := i.accessTokens[accessToken]
	if !ok {
		audit.Log(ctx, log.Logger(), audit.InvalidOAuthTokenEvent).
			Info("Client tried retrieving credential over OIDC4VCI with unknown OAuth2 access token")
		return vc.VerifiableCredential{}, errors.New("invalid access token")
	}
	credential, _ := i.state[preAuthorizedCode]
	subjectDID, _ := getSubjectDID(credential)
	// Important: since we (for now) create the VC even before the wallet requests it, we don't know if every VC is actually retrieved by the wallet.
	//            This is a temporary shortcut, since changing that requires a lot of refactoring.
	//            To make actually retrieved VC traceable, we log it to the audit log.
	audit.Log(ctx, log.Logger(), audit.VerifiableCredentialRetrievedEvent).
		WithField(core.LogFieldCredentialID, credential.ID).
		WithField(core.LogFieldCredentialIssuer, credential.Issuer.String()).
		WithField(core.LogFieldCredentialSubject, subjectDID).
		Infof("VC retrieved by wallet over OIDC4VCI")
	// TODO: this is probably not correct, I think I read in the RFC that the VC should be retrievable multiple times
	//       See https://github.com/nuts-foundation/nuts-node/issues/2031
	delete(i.accessTokens, accessToken)
	delete(i.state, preAuthorizedCode)
	return credential, nil
}

func getSubjectDID(verifiableCredential vc.VerifiableCredential) (string, error) {
	type subjectType struct {
		ID string `json:"id"`
	}
	var subject []subjectType
	err := verifiableCredential.UnmarshalCredentialSubject(&subject)
	if err != nil {
		return "", fmt.Errorf("unable to unmarshal credential subject: %w", err)
	}
	if len(subject) == 0 {
		return "", errors.New("missing subject ID")
	}
	return subject[0].ID, err
}

func generateCode() string {
	// TODO: Replace with something securer?
	//		 See https://github.com/nuts-foundation/nuts-node/issues/2030
	buf := make([]byte, 64)
	_, err := rand.Read(buf)
	if err != nil {
		panic(err)
	}
	return base64.URLEncoding.EncodeToString(buf)
}

func (i *memoryIssuer) getIdentifier(issuerDID string) string {
	return i.baseURL + url.PathEscape(issuerDID)
}

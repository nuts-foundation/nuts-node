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
	crypt "crypto"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/lestrrat-go/jwx/jws"
	"github.com/lestrrat-go/jwx/jwt"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/audit"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/vcr/log"
	"github.com/nuts-foundation/nuts-node/vcr/oidc4vci"
	"github.com/nuts-foundation/nuts-node/vdr/types"
	"net/http"
	"net/url"
	"sync"
	"time"
)

// ErrUnknownIssuer is returned when the given issuer is unknown.
var ErrUnknownIssuer = errors.New("unknown OIDC4VCI issuer")
var _ OIDCIssuer = (*memoryIssuer)(nil)

// OIDCIssuer defines the interface for an OIDC4VCI credential issuer. It is multi-tenant, accompanying the system
// managing an arbitrary number of actual issuers.
type OIDCIssuer interface {
	// ProviderMetadata returns the OpenID Connect provider metadata for the given issuer.
	ProviderMetadata(issuer did.DID) (oidc4vci.ProviderMetadata, error)
	// HandleAccessTokenRequest handles an OAuth2 access token request for the given issuer and pre-authorized code.
	HandleAccessTokenRequest(ctx context.Context, issuer did.DID, preAuthorizedCode string) (string, error)
	// Metadata returns the OIDC4VCI credential issuer metadata for the given issuer.
	Metadata(issuer did.DID) (oidc4vci.CredentialIssuerMetadata, error)
	// OfferCredential sends a credential offer to the specified wallet. It derives the issuer from the credential.
	OfferCredential(ctx context.Context, credential vc.VerifiableCredential, walletURL string) error
	// HandleCredentialRequest requests a credential from the given issuer.
	HandleCredentialRequest(ctx context.Context, issuer did.DID, request oidc4vci.CredentialRequest, accessToken string) (*vc.VerifiableCredential, error)
}

// NewOIDCIssuer creates a new Issuer instance. The identifier is the Credential Issuer Identifier, e.g. https://example.com/issuer/
func NewOIDCIssuer(baseURL string, keyResolver types.KeyResolver) OIDCIssuer {
	return &memoryIssuer{
		baseURL:             baseURL,
		keyResolver:         keyResolver,
		state:               make(map[string]vc.VerifiableCredential),
		accessTokens:        make(map[string]string),
		mux:                 &sync.Mutex{},
		walletClientCreator: oidc4vci.NewWalletAPIClient,
	}
}

type memoryIssuer struct {
	baseURL     string
	keyResolver types.KeyResolver
	// state maps a pre-authorized code to a Verifiable Credential
	state map[string]vc.VerifiableCredential
	// accessToken maps an access token to a pre-authorized code
	accessTokens        map[string]string
	mux                 *sync.Mutex
	walletClientCreator func(ctx context.Context, httpClient *http.Client, walletMetadataURL string) (oidc4vci.WalletAPIClient, error)
}

func (i *memoryIssuer) Metadata(issuer did.DID) (oidc4vci.CredentialIssuerMetadata, error) {
	// TODO: Check if issuer is served by this instance
	//       See https://github.com/nuts-foundation/nuts-node/issues/2054
	return oidc4vci.CredentialIssuerMetadata{
		CredentialIssuer:   i.getIdentifier(issuer.String()),
		CredentialEndpoint: i.getIdentifier(issuer.String()) + "/issuer/oidc4vci/credential",
		// TODO: This must be configured
		//       See https://github.com/nuts-foundation/nuts-node/issues/2058
		CredentialsSupported: []map[string]interface{}{{"NutsAuthorizationCredential": map[string]interface{}{}}},
	}, nil
}

func (i *memoryIssuer) ProviderMetadata(issuer did.DID) (oidc4vci.ProviderMetadata, error) {
	// TODO: Check if issuer is served by this instance
	//       See https://github.com/nuts-foundation/nuts-node/issues/2054
	return oidc4vci.ProviderMetadata{
		Issuer:        i.getIdentifier(issuer.String()),
		TokenEndpoint: core.JoinURLPaths(i.getIdentifier(issuer.String()), "oidc/token"),
		// TODO: Anonymous access (no client_id) is OK as long as PKIoverheid Private is used,
		// if that requirement is dropped we need to authenticate wallets using client_id.
		// See https://github.com/nuts-foundation/nuts-node/issues/2032
		PreAuthorizedGrantAnonymousAccessSupported: true,
	}, nil
}

func (i *memoryIssuer) HandleAccessTokenRequest(ctx context.Context, issuer did.DID, preAuthorizedCode string) (string, error) {
	// TODO: Check if issuer is served by this instance
	//       See https://github.com/nuts-foundation/nuts-node/issues/2054
	i.mux.Lock()
	defer i.mux.Unlock()
	_, ok := i.state[preAuthorizedCode]
	if !ok {
		audit.Log(ctx, log.Logger(), audit.InvalidOAuthTokenEvent).
			Info("Client tried requesting access token (for OIDC4VCI) with unknown OAuth2 pre-authorized code")
		return "", oidc4vci.Error{
			Err:        errors.New("unknown pre-authorized code"),
			Code:       oidc4vci.InvalidGrant,
			StatusCode: http.StatusBadRequest,
		}
	}
	accessToken := generateCode()
	i.accessTokens[accessToken] = preAuthorizedCode
	return accessToken, nil
}

func (i *memoryIssuer) OfferCredential(ctx context.Context, credential vc.VerifiableCredential, clientMetadataURL string) error {
	// TODO: Check if issuer is served by this instance
	//       See https://github.com/nuts-foundation/nuts-node/issues/2054
	preAuthorizedCode := generateCode()
	subject, err := getSubjectDID(credential)
	if err != nil {
		return err
	}
	log.Logger().
		WithField(core.LogFieldCredentialSubject, subject).
		Infof("Offering credential using OIDC4VCI (client-metadata-url=%s)", clientMetadataURL)

	// TODO: Support TLS
	//       See https://github.com/nuts-foundation/nuts-node/issues/2032
	client, err := i.walletClientCreator(ctx, &http.Client{}, clientMetadataURL)
	if err != nil {
		return err
	}

	offer := i.createOffer(credential, preAuthorizedCode)

	err = client.OfferCredential(ctx, offer)
	if err != nil {
		return fmt.Errorf("unable to offer credential (client-metadata-url=%s): %w", client.Metadata().CredentialOfferEndpoint, err)
	}
	return nil
}

func (i *memoryIssuer) HandleCredentialRequest(ctx context.Context, issuer did.DID, request oidc4vci.CredentialRequest, accessToken string) (*vc.VerifiableCredential, error) {
	// TODO: Check if issuer is served by this instance
	//       See https://github.com/nuts-foundation/nuts-node/issues/2054
	i.mux.Lock()
	defer i.mux.Unlock()
	// TODO: Verify requested format and credential definition
	//       See https://github.com/nuts-foundation/nuts-node/issues/2037
	preAuthorizedCode, ok := i.accessTokens[accessToken]
	if !ok {
		audit.Log(ctx, log.Logger(), audit.InvalidOAuthTokenEvent).
			Info("Client tried retrieving credential over OIDC4VCI with unknown OAuth2 access token")
		return nil, oidc4vci.Error{
			Err:        errors.New("unknown access token"),
			Code:       oidc4vci.InvalidToken,
			StatusCode: http.StatusBadRequest,
		}
	}
	credential, _ := i.state[preAuthorizedCode]
	subjectDID, _ := getSubjectDID(credential)

	if err := i.validateProof(request, issuer, subjectDID); err != nil {
		return nil, err
	}

	// Important: since we (for now) create the VC even before the wallet requests it, we don't know if every VC is actually retrieved by the wallet.
	//            This is a temporary shortcut, since changing that requires a lot of refactoring.
	//            To make actually retrieved VC traceable, we log it to the audit log.
	audit.Log(ctx, log.Logger(), audit.VerifiableCredentialRetrievedEvent).
		WithField(core.LogFieldCredentialID, credential.ID).
		WithField(core.LogFieldCredentialIssuer, credential.Issuer.String()).
		WithField(core.LogFieldCredentialSubject, subjectDID).
		Info("VC retrieved by wallet over OIDC4VCI")
	// TODO: this is probably not correct, I think I read in the RFC that the VC should be retrievable multiple times
	//       See https://github.com/nuts-foundation/nuts-node/issues/2031
	delete(i.accessTokens, accessToken)
	delete(i.state, preAuthorizedCode)
	return &credential, nil
}

func (i *memoryIssuer) validateProof(request oidc4vci.CredentialRequest, issuer did.DID, wallet did.DID) error {
	if request.Proof == nil {
		return oidc4vci.Error{
			Err:        errors.New("missing proof"),
			Code:       oidc4vci.InvalidOrMissingProof,
			StatusCode: http.StatusBadRequest,
		}
	}
	if request.Proof.ProofType != oidc4vci.ProofTypeJWT {
		return oidc4vci.Error{
			Err:        errors.New("proof type not supported"),
			Code:       oidc4vci.InvalidOrMissingProof,
			StatusCode: http.StatusBadRequest,
		}
	}
	token, err := crypto.ParseJWT(request.Proof.Jwt, func(kid string) (crypt.PublicKey, error) {
		// Check proof signer == offer receiver
		signerDID, err := did.ParseDIDURL(kid)
		if err != nil {
			return nil, oidc4vci.Error{
				Err:        fmt.Errorf("invalid signing key ID (kid=%s): %w", kid, err),
				Code:       oidc4vci.InvalidOrMissingProof,
				StatusCode: http.StatusBadRequest,
			}
		}
		signerDID.Fragment = ""
		signerDID.Query = ""
		if signerDID.String() != wallet.String() {
			return nil, oidc4vci.Error{
				Err:        fmt.Errorf("credential offer wasn't intended for wallet: %s", wallet),
				Code:       oidc4vci.InvalidOrMissingProof,
				StatusCode: http.StatusBadRequest,
			}
		}

		// Assert proof is actually signed by wallet to which it was offered (key must be present on DID document)
		signingKey, err := i.keyResolver.ResolveSigningKey(kid, nil)
		if err != nil {
			return nil, fmt.Errorf("unable to resolve signing key (kid=%s): %w", kid, err)
		}

		return signingKey, nil
	}, jwt.WithAcceptableSkew(5*time.Second))
	if err != nil {
		return oidc4vci.Error{
			Err:        err,
			Code:       oidc4vci.InvalidOrMissingProof,
			StatusCode: http.StatusBadRequest,
		}
	}

	// Validate audience
	audienceMatches := false
	for _, aud := range token.Audience() {
		if aud == i.getIdentifier(issuer.String()) {
			audienceMatches = true
			break
		}
	}
	if !audienceMatches {
		return oidc4vci.Error{
			Err:        fmt.Errorf("audience doesn't match credential issuer (aud=%s)", token.Audience()),
			Code:       oidc4vci.InvalidOrMissingProof,
			StatusCode: http.StatusBadRequest,
		}
	}

	// Validate JWT type
	// jwt.Parse does not provide the JWS headers, we have to parse it again as JWS to access those
	message, err := jws.ParseString(request.Proof.Jwt)
	if err != nil {
		// Should not fail
		return err
	}
	if len(message.Signatures()) != 1 {
		// I think this is impossible
		return errors.New("expected exactly one signature")
	}
	typ := message.Signatures()[0].ProtectedHeaders().Type()
	if typ == "" {
		return oidc4vci.Error{
			Err:        errors.New("missing typ header"),
			Code:       oidc4vci.InvalidOrMissingProof,
			StatusCode: http.StatusBadRequest,
		}
	}
	if typ != oidc4vci.JWTTypeOpenID4VCIProof {
		return oidc4vci.Error{
			Err:        fmt.Errorf("invalid typ claim (expected: %s): %s", oidc4vci.JWTTypeOpenID4VCIProof, typ),
			Code:       oidc4vci.InvalidOrMissingProof,
			StatusCode: http.StatusBadRequest,
		}
	}

	// TODO: Check nonce value when we've implemented safe nonce handling
	//       See https://github.com/nuts-foundation/nuts-node/issues/2051

	return nil
}

func (i *memoryIssuer) createOffer(credential vc.VerifiableCredential, preAuthorizedCode string) oidc4vci.CredentialOffer {
	offer := oidc4vci.CredentialOffer{
		CredentialIssuer: i.getIdentifier(credential.Issuer.String()),
		Credentials: []map[string]interface{}{{
			"format": oidc4vci.VerifiableCredentialJSONLDFormat,
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

	i.mux.Lock()
	i.state[preAuthorizedCode] = credential
	i.mux.Unlock()
	return offer
}

func getSubjectDID(verifiableCredential vc.VerifiableCredential) (did.DID, error) {
	type subjectType struct {
		ID did.DID `json:"id"`
	}
	var subject []subjectType
	err := verifiableCredential.UnmarshalCredentialSubject(&subject)
	if err != nil {
		return did.DID{}, fmt.Errorf("unable to unmarshal credential subject: %w", err)
	}
	if len(subject) == 0 {
		return did.DID{}, errors.New("missing subject ID")
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
	return core.JoinURLPaths(i.baseURL, url.PathEscape(issuerDID))
}

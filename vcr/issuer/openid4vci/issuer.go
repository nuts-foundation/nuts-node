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

package openid4vci

import (
	"context"
	crypt "crypto"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/jws"
	"github.com/lestrrat-go/jwx/jwt"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/audit"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/vcr/log"
	"github.com/nuts-foundation/nuts-node/vcr/oidc4vci"
	"github.com/nuts-foundation/nuts-node/vdr/didservice"
	"github.com/nuts-foundation/nuts-node/vdr/types"
	"net/http"
	"net/url"
	"time"
)

// ErrUnknownIssuer is returned when the given issuer is unknown.
var ErrUnknownIssuer = errors.New("unknown OIDC4VCI issuer")
var _ Issuer = (*issuer)(nil)

// ttl is the time-to-live for issuance flows and nonces.
const ttl = 15 * time.Minute
const preAuthCodeRefType = "preauthcode"
const accessTokenRefType = "accesstoken"

// secretSizeBits is the size of the generated random secrets (access tokens, pre-authorized codes) in bits.
const secretSizeBits = 128

// Issuer defines the interface for an OIDC4VCI credential issuer. It is multi-tenant, accompanying the system
// managing an arbitrary number of actual issuers.
type Issuer interface {
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

// New creates a new Issuer instance. The identifier is the Credential Issuer Identifier, e.g. https://example.com/issuer/
func New(baseURL string, clientTLSConfig *tls.Config, clientTimeout time.Duration, keyResolver types.KeyResolver, store Store) Issuer {
	return &issuer{
		baseURL:             baseURL,
		keyResolver:         keyResolver,
		walletClientCreator: oidc4vci.NewWalletAPIClient,
		clientTimeout:       clientTimeout,
		clientTLSConfig:     clientTLSConfig,
		store:               store,
	}
}

type issuer struct {
	baseURL             string
	keyResolver         types.KeyResolver
	store               Store
	walletClientCreator func(ctx context.Context, httpClient *http.Client, walletMetadataURL string) (oidc4vci.WalletAPIClient, error)
	clientTLSConfig     *tls.Config
	clientTimeout       time.Duration
}

func (i *issuer) Metadata(issuer did.DID) (oidc4vci.CredentialIssuerMetadata, error) {
	return oidc4vci.CredentialIssuerMetadata{
		CredentialIssuer:   i.getIdentifier(issuer.String()),
		CredentialEndpoint: i.getIdentifier(issuer.String()) + "/issuer/oidc4vci/credential",
		// TODO: This must be configured
		//       See https://github.com/nuts-foundation/nuts-node/issues/2058
		CredentialsSupported: []map[string]interface{}{{"NutsAuthorizationCredential": map[string]interface{}{}}},
	}, nil
}

func (i *issuer) ProviderMetadata(issuer did.DID) (oidc4vci.ProviderMetadata, error) {
	return oidc4vci.ProviderMetadata{
		Issuer:        i.getIdentifier(issuer.String()),
		TokenEndpoint: core.JoinURLPaths(i.getIdentifier(issuer.String()), "oidc/token"),
		// TODO: Anonymous access (no client_id) is OK as long as PKIoverheid Private is used,
		// if that requirement is dropped we need to authenticate wallets using client_id.
		// See https://github.com/nuts-foundation/nuts-node/issues/2032
		PreAuthorizedGrantAnonymousAccessSupported: true,
	}, nil
}

func (i *issuer) HandleAccessTokenRequest(ctx context.Context, issuer did.DID, preAuthorizedCode string) (string, error) {
	flow, err := i.store.FindByReference(ctx, preAuthCodeRefType, preAuthorizedCode)
	if err != nil {
		return "", err
	}
	if flow == nil {
		return "", oidc4vci.Error{
			Err:        errors.New("unknown pre-authorized code"),
			Code:       oidc4vci.InvalidGrant,
			StatusCode: http.StatusBadRequest,
		}
	}
	if flow.IssuerID != issuer.String() {
		return "", oidc4vci.Error{
			Err:        errors.New("pre-authorized code not issued by this issuer"),
			Code:       oidc4vci.InvalidGrant,
			StatusCode: http.StatusBadRequest,
		}
	}
	accessToken := generateCode()
	err = i.store.StoreReference(ctx, flow.ID, accessTokenRefType, accessToken, time.Now().Add(ttl))
	if err != nil {
		return "", err
	}
	// PreAuthorizedCode is to be used just once
	// See https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-4.1.1
	// "This code MUST be short lived and single-use."
	err = i.store.DeleteReference(ctx, preAuthCodeRefType, preAuthorizedCode)
	if err != nil {
		// Extremely unlikely, but if we return an error here the credential issuance flow will fail without a way to retry it.
		// Thus just log it, nothing will break (since they'll be pruned after ttl anyway).
		log.Logger().WithError(err).Error("Failed to delete pre-authorized code")
	}
	return accessToken, nil
}

func (i *issuer) OfferCredential(ctx context.Context, credential vc.VerifiableCredential, clientMetadataURL string) error {
	preAuthorizedCode := generateCode()
	subject, err := getSubjectDID(credential)
	if err != nil {
		return err
	}
	log.Logger().
		WithField(core.LogFieldCredentialSubject, subject).
		Infof("Offering credential using OIDC4VCI (client-metadata-url=%s)", clientMetadataURL)

	httpTransport := http.DefaultTransport.(*http.Transport).Clone()
	httpTransport.TLSClientConfig = i.clientTLSConfig
	httpClient := &http.Client{
		Timeout:   i.clientTimeout,
		Transport: httpTransport,
	}
	client, err := i.walletClientCreator(ctx, httpClient, clientMetadataURL)
	if err != nil {
		return err
	}

	offer, err := i.createOffer(ctx, credential, preAuthorizedCode)
	if err != nil {
		return err
	}

	err = client.OfferCredential(ctx, *offer)
	if err != nil {
		return fmt.Errorf("unable to offer credential (client-metadata-url=%s): %w", client.Metadata().CredentialOfferEndpoint, err)
	}
	return nil
}

func (i *issuer) HandleCredentialRequest(ctx context.Context, issuer did.DID, request oidc4vci.CredentialRequest, accessToken string) (*vc.VerifiableCredential, error) {
	// TODO: Check if issuer is served by this instance
	//       See https://github.com/nuts-foundation/nuts-node/issues/2054
	// TODO: Verify requested format and credential definition
	//       See https://github.com/nuts-foundation/nuts-node/issues/2037
	flow, err := i.store.FindByReference(ctx, accessTokenRefType, accessToken)
	if err != nil {
		return nil, err
	}
	if flow == nil {
		log.Logger().Warn("Client tried retrieving credential over OIDC4VCI with unknown OAuth2 access token")
		return nil, oidc4vci.Error{
			Err:        errors.New("unknown access token"),
			Code:       oidc4vci.InvalidToken,
			StatusCode: http.StatusBadRequest,
		}
	}

	credential := flow.Credentials[0] // there's always just one (at least for now)
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

	return &credential, nil
}

// validateProof validates the proof of the credential request. Aside from checks as specified by the spec,
// it verifies the proof signature, and whether the signer is the intended wallet.
// See https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-proof-types
func (i *issuer) validateProof(request oidc4vci.CredentialRequest, issuer did.DID, wallet did.DID) error {
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
	var signingKeyID string
	token, err := crypto.ParseJWT(request.Proof.Jwt, func(kid string) (crypt.PublicKey, error) {
		signingKeyID = kid
		return i.keyResolver.ResolveSigningKey(kid, nil)
	}, jwt.WithAcceptableSkew(5*time.Second))
	if err != nil {
		return oidc4vci.Error{
			Err:        err,
			Code:       oidc4vci.InvalidOrMissingProof,
			StatusCode: http.StatusBadRequest,
		}
	}

	// Proof must be signed by wallet to which it was offered (proof signer == offer receiver)
	if signerDID, err := didservice.GetDIDFromURL(signingKeyID); err != nil || signerDID.String() != wallet.String() {
		return oidc4vci.Error{
			Err:        fmt.Errorf("credential offer was signed by other DID than intended wallet: %s", signingKeyID),
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

func (i *issuer) createOffer(ctx context.Context, credential vc.VerifiableCredential, preAuthorizedCode string) (*oidc4vci.CredentialOffer, error) {
	grantParams := map[string]interface{}{
		"pre-authorized_code": preAuthorizedCode,
	}
	offer := oidc4vci.CredentialOffer{
		CredentialIssuer: i.getIdentifier(credential.Issuer.String()),
		Credentials: []map[string]interface{}{{
			"format": oidc4vci.VerifiableCredentialJSONLDFormat,
			"credential_definition": map[string]interface{}{
				"@context": credential.Context,
				"type":     credential.Type,
			},
		}},
		Grants: map[string]interface{}{
			oidc4vci.PreAuthorizedCodeGrant: grantParams,
		},
	}
	subjectDID, _ := getSubjectDID(credential) // succeeded in previous step, can't fail

	flow := Flow{
		ID:          uuid.NewString(),
		IssuerID:    credential.Issuer.String(),
		WalletID:    subjectDID.String(),
		Expiry:      time.Now().Add(ttl),
		Credentials: []vc.VerifiableCredential{credential},
		Grants: []Grant{
			{
				Type:   oidc4vci.PreAuthorizedCodeGrant,
				Params: grantParams,
			},
		},
	}
	err := i.store.Store(ctx, flow)
	if err == nil {
		err = i.store.StoreReference(ctx, flow.ID, preAuthCodeRefType, preAuthorizedCode, time.Now().Add(ttl))
	}
	if err != nil {
		return nil, fmt.Errorf("unable to store credential offer: %w", err)
	}
	return &offer, nil
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

func (i *issuer) getIdentifier(issuerDID string) string {
	return core.JoinURLPaths(i.baseURL, url.PathEscape(issuerDID))
}

func generateCode() string {
	buf := make([]byte, secretSizeBits/8)
	_, err := rand.Read(buf)
	if err != nil {
		panic(err)
	}
	return base64.URLEncoding.EncodeToString(buf)
}

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
	"encoding/json"
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
	"github.com/nuts-foundation/nuts-node/vcr/issuer/assets"
	"github.com/nuts-foundation/nuts-node/vcr/log"
	"github.com/nuts-foundation/nuts-node/vcr/openid4vci"
	"github.com/nuts-foundation/nuts-node/vdr/didservice"
	"github.com/nuts-foundation/nuts-node/vdr/types"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

// Flow is an active OpenID4VCI credential issuance flow.
type Flow struct {
	ID string `json:"id"`
	// IssuerID is the identifier of the credential issuer.
	IssuerID string `json:"issuer_id"`
	// WalletID is the identifier of the wallet.
	WalletID string `json:"wallet_id"`
	// Grants is a list of grants that can be used to acquire an access token.
	Grants []Grant `json:"grants"`
	// Credentials is the list of Verifiable Credentials that be issued to the wallet through this flow.
	// It might be pre-determined (in the issuer-initiated flow) or determined during the flow execution (in the wallet-initiated flow).
	Credentials []vc.VerifiableCredential `json:"credentials"`
	Expiry      time.Time                 `json:"exp"`
}

// Nonce is a nonce that has been issued for an OpenID4VCI flow, to be used by the wallet when requesting credentials.
// A nonce can only be used once (doh), and is only valid for a certain period of time.
type Nonce struct {
	Nonce  string    `json:"nonce"`
	Expiry time.Time `json:"exp"`
}

// Grant is a grant that has been issued for an OAuth2 state.
type Grant struct {
	// Type is the type of grant, e.g. "urn:ietf:params:oauth:grant-type:pre-authorized_code".
	Type string `json:"type"`
	// Params is a map of parameters for the grant, e.g. "pre-authorized_code" for type "urn:ietf:params:oauth:grant-type:pre-authorized_code".
	Params map[string]interface{} `json:"params"`
}

// ErrUnknownIssuer is returned when the given issuer is unknown.
var ErrUnknownIssuer = errors.New("unknown OpenID4VCI issuer")
var _ OpenIDHandler = (*openidHandler)(nil)

// TokenTTL is the time-to-live for issuance flows, access tokens and nonces.
const TokenTTL = 15 * time.Minute

const preAuthCodeRefType = "preauthcode"
const accessTokenRefType = "accesstoken"
const cNonceRefType = "c_nonce"

// openidSecretSizeBits is the size of the generated random secrets (access tokens, pre-authorized codes) in bits.
const openidSecretSizeBits = 128

// OpenIDHandler defines the interface for handling OpenID4VCI issuer operations.
type OpenIDHandler interface {
	// ProviderMetadata returns the OpenID Connect provider metadata.
	ProviderMetadata() openid4vci.ProviderMetadata
	// HandleAccessTokenRequest handles an OAuth2 access token request for the given issuer and pre-authorized code.
	// It returns the access token and a c_nonce.
	HandleAccessTokenRequest(ctx context.Context, preAuthorizedCode string) (string, string, error)
	// Metadata returns the OpenID4VCI credential issuer metadata for the given issuer.
	Metadata() openid4vci.CredentialIssuerMetadata
	// OfferCredential sends a credential offer to the specified wallet. It derives the issuer from the credential.
	OfferCredential(ctx context.Context, credential vc.VerifiableCredential, walletIdentifier string) error
	// HandleCredentialRequest requests a credential from the given issuer.
	HandleCredentialRequest(ctx context.Context, request openid4vci.CredentialRequest, accessToken string) (*vc.VerifiableCredential, error)
}

// NewOpenIDHandler creates a new OpenIDHandler instance. The identifier is the Credential Issuer Identifier, e.g. https://example.com/issuer/
func NewOpenIDHandler(issuerDID did.DID, issuerIdentifierURL string, definitionsDIR string, config openid4vci.ClientConfig, keyResolver types.KeyResolver, store OpenIDStore) (OpenIDHandler, error) {
	i := &openidHandler{
		issuerIdentifierURL: issuerIdentifierURL,
		issuerDID:           issuerDID,
		definitionsDIR:      definitionsDIR,
		config:              config,
		keyResolver:         keyResolver,
		walletClientCreator: openid4vci.NewWalletAPIClient,
		store:               store,
	}

	// load the credential definitions. This is done to halt startup procedure if needed.
	return i, i.loadCredentialDefinitions()
}

type openidHandler struct {
	issuerIdentifierURL  string
	issuerDID            did.DID
	definitionsDIR       string
	credentialsSupported []map[string]interface{}
	config               openid4vci.ClientConfig
	keyResolver          types.KeyResolver
	store                OpenIDStore
	walletClientCreator  func(ctx context.Context, httpClient core.HTTPRequestDoer, walletMetadataURL string) (openid4vci.WalletAPIClient, error)
}

func (i *openidHandler) Metadata() openid4vci.CredentialIssuerMetadata {
	metadata := openid4vci.CredentialIssuerMetadata{
		CredentialIssuer:   i.issuerIdentifierURL,
		CredentialEndpoint: core.JoinURLPaths(i.issuerIdentifierURL, "/issuer/openid4vci/credential"),
	}

	// deepcopy the i.credentialsSupported slice to prevent concurrent access to the slice.
	metadata.CredentialsSupported = deepcopy(i.credentialsSupported)

	return metadata
}

func (i *openidHandler) ProviderMetadata() openid4vci.ProviderMetadata {
	return openid4vci.ProviderMetadata{
		Issuer:        i.issuerIdentifierURL,
		TokenEndpoint: core.JoinURLPaths(i.issuerIdentifierURL, "oidc/token"),
		// TODO: Anonymous access (no client_id) is OK as long as PKIoverheid Private is used,
		// if that requirement is dropped we need to authenticate wallets using client_id.
		// See https://github.com/nuts-foundation/nuts-node/issues/2032
		PreAuthorizedGrantAnonymousAccessSupported: true,
	}
}

func (i *openidHandler) HandleAccessTokenRequest(ctx context.Context, preAuthorizedCode string) (string, string, error) {
	flow, err := i.store.FindByReference(ctx, preAuthCodeRefType, preAuthorizedCode)
	if err != nil {
		return "", "", err
	}
	if flow == nil {
		return "", "", openid4vci.Error{
			Err:        errors.New("unknown pre-authorized code"),
			Code:       openid4vci.InvalidGrant,
			StatusCode: http.StatusBadRequest,
		}
	}
	if flow.IssuerID != i.issuerDID.String() {
		return "", "", openid4vci.Error{
			Err:        errors.New("pre-authorized code not issued by this issuer"),
			Code:       openid4vci.InvalidGrant,
			StatusCode: http.StatusBadRequest,
		}
	}
	accessToken := generateCode()
	err = i.store.StoreReference(ctx, flow.ID, accessTokenRefType, accessToken, time.Now().Add(TokenTTL))
	if err != nil {
		return "", "", err
	}
	cNonce := generateCode()
	err = i.store.StoreReference(ctx, flow.ID, cNonceRefType, cNonce, time.Now().Add(TokenTTL))
	if err != nil {
		return "", "", err
	}

	// PreAuthorizedCode is to be used just once
	// See https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-4.1.1
	// "This code MUST be short-lived and single-use."
	err = i.store.DeleteReference(ctx, preAuthCodeRefType, preAuthorizedCode)
	if err != nil {
		// Extremely unlikely, but if we return an error here the credential issuance flow will fail without a way to retry it.
		// Just log it, nothing will break (since they'll be pruned after ttl anyway).
		log.Logger().WithError(err).Error("Failed to delete pre-authorized code")
	}
	return accessToken, cNonce, nil
}

func (i *openidHandler) OfferCredential(ctx context.Context, credential vc.VerifiableCredential, walletIdentifier string) error {
	preAuthorizedCode := generateCode()
	walletMetadataURL := core.JoinURLPaths(walletIdentifier, openid4vci.WalletMetadataWellKnownPath)
	log.Logger().
		WithField(core.LogFieldCredentialID, credential.ID).
		Infof("Offering credential using OpenID4VCI (client-metadata-url=%s)", walletMetadataURL)

	httpTransport := http.DefaultTransport.(*http.Transport).Clone()
	httpTransport.TLSClientConfig = i.config.TLS
	httpClient := core.NewStrictHTTPClient(i.config.HTTPSOnly, &http.Client{
		Timeout:   i.config.Timeout,
		Transport: httpTransport,
	})
	client, err := i.walletClientCreator(ctx, httpClient, walletMetadataURL)
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

func (i *openidHandler) HandleCredentialRequest(ctx context.Context, request openid4vci.CredentialRequest, accessToken string) (*vc.VerifiableCredential, error) {
	if request.Format != openid4vci.VerifiableCredentialJSONLDFormat {
		return nil, openid4vci.Error{
			Err:        fmt.Errorf("credential request: unsupported format '%s'", request.Format),
			Code:       openid4vci.UnsupportedCredentialType,
			StatusCode: http.StatusBadRequest,
		}
	}
	if err := request.CredentialDefinition.Validate(false); err != nil {
		return nil, openid4vci.Error{
			Err:        fmt.Errorf("credential request: %w", err),
			Code:       openid4vci.InvalidRequest,
			StatusCode: http.StatusBadRequest,
		}
	}
	flow, err := i.store.FindByReference(ctx, accessTokenRefType, accessToken)
	if err != nil {
		return nil, err
	}
	if flow == nil {
		log.Logger().Warn("Client tried retrieving credential over OpenID4VCI with unknown OAuth2 access token")
		return nil, openid4vci.Error{
			Err:        errors.New("unknown access token"),
			Code:       openid4vci.InvalidToken,
			StatusCode: http.StatusBadRequest,
		}
	}

	credential := flow.Credentials[0] // there's always just one (at least for now)
	subjectDID, _ := getSubjectDID(credential)

	// check credential.Issuer against given issuer
	if credential.Issuer.String() != i.issuerDID.String() {
		return nil, openid4vci.Error{
			Err:        errors.New("credential issuer does not match given issuer"),
			Code:       openid4vci.InvalidRequest,
			StatusCode: http.StatusBadRequest,
		}
	}

	if err = i.validateProof(ctx, flow, request); err != nil {
		return nil, err
	}

	if err = openid4vci.ValidateDefinitionWithCredential(credential, *request.CredentialDefinition); err != nil {
		return nil, openid4vci.Error{
			Err:        fmt.Errorf("requested credential does not match offer: %w", err),
			Code:       openid4vci.InvalidRequest,
			StatusCode: http.StatusBadRequest,
		}
	}

	// Important: since we (for now) create the VC even before the wallet requests it, we don't know if every VC is actually retrieved by the wallet.
	//            This is a temporary shortcut, since changing that requires a lot of refactoring.
	//            To make actually retrieved VC traceable, we log it to the audit log.
	audit.Log(ctx, log.Logger(), audit.VerifiableCredentialRetrievedEvent).
		WithField(core.LogFieldCredentialID, credential.ID).
		WithField(core.LogFieldCredentialIssuer, credential.Issuer.String()).
		WithField(core.LogFieldCredentialSubject, subjectDID).
		Info("VC retrieved by wallet over OpenID4VCI")

	return &credential, nil
}

// validateProof validates the proof of the credential request. Aside from checks as specified by the spec,
// it verifies the proof signature, and whether the signer is the intended wallet.
// See https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-proof-types
func (i *openidHandler) validateProof(ctx context.Context, flow *Flow, request openid4vci.CredentialRequest) error {
	credential := flow.Credentials[0] // there's always just one (at least for now)
	wallet, _ := getSubjectDID(credential)

	// augment invalid_proof errors according to §7.3.2 of openid4vci spec
	generateProofError := func(err openid4vci.Error) error {
		cnonce := generateCode()
		if err := i.store.StoreReference(ctx, flow.ID, cNonceRefType, cnonce, time.Now().Add(TokenTTL)); err != nil {
			return err
		}
		expiry := int(TokenTTL.Seconds())
		err.CNonce = &cnonce
		err.CNonceExpiresIn = &expiry
		return err
	}

	if request.Proof == nil {
		return generateProofError(openid4vci.Error{
			Err:        errors.New("missing proof"),
			Code:       openid4vci.InvalidProof,
			StatusCode: http.StatusBadRequest,
		})
	}
	if request.Proof.ProofType != openid4vci.ProofTypeJWT {
		return generateProofError(openid4vci.Error{
			Err:        errors.New("proof type not supported"),
			Code:       openid4vci.InvalidProof,
			StatusCode: http.StatusBadRequest,
		})
	}
	var signingKeyID string
	token, err := crypto.ParseJWT(request.Proof.Jwt, func(kid string) (crypt.PublicKey, error) {
		signingKeyID = kid
		return i.keyResolver.ResolveSigningKey(kid, nil)
	}, jwt.WithAcceptableSkew(5*time.Second))
	if err != nil {
		return generateProofError(openid4vci.Error{
			Err:        err,
			Code:       openid4vci.InvalidProof,
			StatusCode: http.StatusBadRequest,
		})
	}

	// Proof must be signed by wallet to which it was offered (proof signer == offer receiver)
	if signerDID, err := didservice.GetDIDFromURL(signingKeyID); err != nil || signerDID.String() != wallet.String() {
		return generateProofError(openid4vci.Error{
			Err:        fmt.Errorf("credential offer was signed by other DID than intended wallet: %s", signingKeyID),
			Code:       openid4vci.InvalidProof,
			StatusCode: http.StatusBadRequest,
		})
	}

	// Validate audience
	audienceMatches := false
	for _, aud := range token.Audience() {
		if aud == i.issuerIdentifierURL {
			audienceMatches = true
			break
		}
	}
	if !audienceMatches {
		return generateProofError(openid4vci.Error{
			Err:        fmt.Errorf("audience doesn't match credential issuer (aud=%s)", token.Audience()),
			Code:       openid4vci.InvalidProof,
			StatusCode: http.StatusBadRequest,
		})
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
		return generateProofError(openid4vci.Error{
			Err:        errors.New("missing typ header"),
			Code:       openid4vci.InvalidProof,
			StatusCode: http.StatusBadRequest,
		})
	}
	if typ != openid4vci.JWTTypeOpenID4VCIProof {
		return generateProofError(openid4vci.Error{
			Err:        fmt.Errorf("invalid typ claim (expected: %s): %s", openid4vci.JWTTypeOpenID4VCIProof, typ),
			Code:       openid4vci.InvalidProof,
			StatusCode: http.StatusBadRequest,
		})
	}

	// given the JWT typ, the nonce is in the 'nonce' claim
	nonce, ok := token.Get("nonce")
	if !ok {
		return generateProofError(openid4vci.Error{
			Err:        errors.New("missing nonce claim"),
			Code:       openid4vci.InvalidProof,
			StatusCode: http.StatusBadRequest,
		})
	}

	// check if the nonce matches the one we sent in the offer
	flowFromNonce, err := i.store.FindByReference(ctx, cNonceRefType, nonce.(string))
	if err != nil {
		return err
	}
	if flowFromNonce == nil {
		return openid4vci.Error{
			Err:        errors.New("unknown nonce"),
			Code:       openid4vci.InvalidProof,
			StatusCode: http.StatusBadRequest,
		}
	}
	if flowFromNonce.ID != flow.ID {
		return openid4vci.Error{
			Err:        errors.New("nonce not valid for access token"),
			Code:       openid4vci.InvalidProof,
			StatusCode: http.StatusBadRequest,
		}
	}

	return nil
}

func (i *openidHandler) createOffer(ctx context.Context, credential vc.VerifiableCredential, preAuthorizedCode string) (*openid4vci.CredentialOffer, error) {
	grantParams := map[string]interface{}{
		"pre-authorized_code": preAuthorizedCode,
	}
	offer := openid4vci.CredentialOffer{
		CredentialIssuer: i.issuerIdentifierURL,
		Credentials: []openid4vci.OfferedCredential{{
			Format: openid4vci.VerifiableCredentialJSONLDFormat,
			CredentialDefinition: &openid4vci.CredentialDefinition{
				Context: credential.Context,
				Type:    credential.Type,
			},
		}},
		Grants: map[string]interface{}{
			openid4vci.PreAuthorizedCodeGrant: grantParams,
		},
	}
	subjectDID, _ := getSubjectDID(credential) // succeeded in previous step, can't fail

	flow := Flow{
		ID:          uuid.NewString(),
		IssuerID:    credential.Issuer.String(),
		WalletID:    subjectDID.String(),
		Expiry:      time.Now().Add(TokenTTL),
		Credentials: []vc.VerifiableCredential{credential},
		Grants: []Grant{
			{
				Type:   openid4vci.PreAuthorizedCodeGrant,
				Params: grantParams,
			},
		},
	}
	err := i.store.Store(ctx, flow)
	if err == nil {
		err = i.store.StoreReference(ctx, flow.ID, preAuthCodeRefType, preAuthorizedCode, time.Now().Add(TokenTTL))
	}
	if err != nil {
		return nil, fmt.Errorf("unable to store credential offer: %w", err)
	}
	return &offer, nil
}

func (i *openidHandler) loadCredentialDefinitions() error {

	// retrieve the definitions from assets and add to the list of CredentialsSupported
	definitionsDir, err := assets.FS.ReadDir("definitions")
	if err != nil {
		return err
	}
	for _, definition := range definitionsDir {
		definitionData, err := assets.FS.ReadFile(fmt.Sprintf("definitions/%s", definition.Name()))
		if err != nil {
			return err
		}
		var definitionMap map[string]interface{}
		err = json.Unmarshal(definitionData, &definitionMap)
		if err != nil {
			return err
		}
		i.credentialsSupported = append(i.credentialsSupported, definitionMap)
	}

	// now add all credential definition from config.DefinitionsDIR
	if i.definitionsDIR != "" {
		err = filepath.WalkDir(i.definitionsDIR, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return fmt.Errorf("failed to load credential definitions: %w", err)
			}
			if !d.IsDir() && filepath.Ext(path) == ".json" {
				definitionData, err := os.ReadFile(path)
				if err != nil {
					return fmt.Errorf("failed to read credential definition from %s: %w", path, err)
				}
				var definitionMap map[string]interface{}
				err = json.Unmarshal(definitionData, &definitionMap)
				if err != nil {
					return fmt.Errorf("failed to parse credential definition from %s: %w", path, err)
				}
				i.credentialsSupported = append(i.credentialsSupported, definitionMap)
			}
			return nil
		})
	}

	return err

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
	buf := make([]byte, openidSecretSizeBits/8)
	_, err := rand.Read(buf)
	if err != nil {
		panic(err)
	}
	return base64.URLEncoding.EncodeToString(buf)
}

func deepcopy(src []map[string]interface{}) []map[string]interface{} {
	dst := make([]map[string]interface{}, len(src))
	for i := range src {
		dst[i] = make(map[string]interface{})
		for k, v := range src[i] {
			dst[i][k] = v
		}
	}
	return dst
}

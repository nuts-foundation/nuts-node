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
	"encoding/json"
	"errors"
	"fmt"
	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/audit"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/storage"
	"github.com/nuts-foundation/nuts-node/vcr/issuer/assets"
	"github.com/nuts-foundation/nuts-node/vcr/log"
	"github.com/nuts-foundation/nuts-node/vcr/openid4vci"
	"github.com/nuts-foundation/nuts-node/vdr/resolver"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

// openID4VCIProofProfile defines JWT validation rules for OpenID4VCI proof JWTs.
// aud must equal the credential issuer identifier (see the spec §7.2.1); the post-parse
// check against i.issuerIdentifierURL still runs to compare the actual value.
var openID4VCIProofProfile = &crypto.JWTProfile{
	Typ:            openid4vci.JWTTypeOpenID4VCIProof,
	RequiredClaims: []string{jwt.IssuedAtKey, jwt.AudienceKey},
}

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
}

// Grant is a grant that has been issued for an OAuth2 state.
type Grant struct {
	// Type is the type of grant, e.g. "urn:ietf:params:oauth:grant-type:pre-authorized_code".
	Type string `json:"type"`
	// Params is a map of parameters for the grant, e.g. "pre-authorized_code" for type "urn:ietf:params:oauth:grant-type:pre-authorized_code".
	Params map[string]interface{} `json:"params"`
}

var _ OpenIDHandler = (*openidHandler)(nil)

// TokenTTL is the time-to-live for issuance flows, access tokens and nonces.
const TokenTTL = 15 * time.Minute

const preAuthCodeRefType = "preauthcode"
const accessTokenRefType = "accesstoken"

// OpenIDHandler defines the interface for handling OpenID4VCI issuer operations.
type OpenIDHandler interface {
	// ProviderMetadata returns the OpenID Connect provider metadata.
	ProviderMetadata() openid4vci.ProviderMetadata
	// HandleAccessTokenRequest handles an OAuth2 access token request for the given issuer and pre-authorized code.
	// It returns the access token.
	HandleAccessTokenRequest(ctx context.Context, preAuthorizedCode string) (string, error)
	// Metadata returns the OpenID4VCI credential issuer metadata for the given issuer.
	Metadata() openid4vci.CredentialIssuerMetadata
	// OfferCredential sends a credential offer to the specified wallet. It derives the issuer from the credential.
	OfferCredential(ctx context.Context, credential vc.VerifiableCredential, walletIdentifier string) error
	// HandleCredentialRequest requests a credential from the given issuer.
	HandleCredentialRequest(ctx context.Context, request openid4vci.CredentialRequest, accessToken string) (*vc.VerifiableCredential, error)
	// HandleNonceRequest handles a request to the Nonce Endpoint (v1.0 Section 7).
	// It generates a standalone nonce and returns it.
	HandleNonceRequest(ctx context.Context) (string, error)
}

// NewOpenIDHandler creates a new OpenIDHandler instance. The identifier is the Credential Issuer Identifier, e.g. https://example.com/issuer/
func NewOpenIDHandler(issuerDID did.DID, issuerIdentifierURL string, definitionsDIR string, httpClient core.HTTPRequestDoer, keyResolver resolver.KeyResolver, sessionDatabase storage.SessionDatabase) (OpenIDHandler, error) {
	i := &openidHandler{
		issuerIdentifierURL: issuerIdentifierURL,
		issuerDID:           issuerDID,
		definitionsDIR:      definitionsDIR,
		httpClient:          httpClient,
		keyResolver:         keyResolver,
		walletClientCreator: openid4vci.NewWalletAPIClient,
		store:               NewOpenIDMemoryStore(sessionDatabase),
	}

	// load the credential definitions. This is done to halt startup procedure if needed.
	return i, i.loadCredentialDefinitions()
}

type openidHandler struct {
	issuerIdentifierURL              string
	issuerDID                        did.DID
	definitionsDIR                   string
	credentialConfigurationsSupported map[string]map[string]interface{}
	keyResolver                      resolver.KeyResolver
	store                            OpenIDStore
	walletClientCreator              func(ctx context.Context, httpClient core.HTTPRequestDoer, walletMetadataURL string) (openid4vci.WalletAPIClient, error)
	httpClient                       core.HTTPRequestDoer
}

func (i *openidHandler) Metadata() openid4vci.CredentialIssuerMetadata {
	metadata := openid4vci.CredentialIssuerMetadata{
		CredentialIssuer:   i.issuerIdentifierURL,
		CredentialEndpoint: core.JoinURLPaths(i.issuerIdentifierURL, "/openid4vci/credential"),
		NonceEndpoint:      core.JoinURLPaths(i.issuerIdentifierURL, "/openid4vci/nonce"),
	}

	// deepcopy the credentialConfigurationsSupported map to prevent concurrent access.
	metadata.CredentialConfigurationsSupported = deepcopyMap(i.credentialConfigurationsSupported)

	return metadata
}

func (i *openidHandler) ProviderMetadata() openid4vci.ProviderMetadata {
	return openid4vci.ProviderMetadata{
		Issuer:        i.issuerIdentifierURL,
		TokenEndpoint: core.JoinURLPaths(i.issuerIdentifierURL, "token"),
		// TODO: Anonymous access (no client_id) is OK as long as PKIoverheid Private is used,
		// if that requirement is dropped we need to authenticate wallets using client_id.
		// See https://github.com/nuts-foundation/nuts-node/issues/2032
		PreAuthorizedGrantAnonymousAccessSupported: true,
	}
}

func (i *openidHandler) HandleAccessTokenRequest(ctx context.Context, preAuthorizedCode string) (string, error) {
	flow, err := i.store.FindByReference(ctx, preAuthCodeRefType, preAuthorizedCode)
	if err != nil {
		return "", err
	}
	if flow == nil {
		return "", openid4vci.Error{
			Err:        errors.New("unknown pre-authorized code"),
			Code:       openid4vci.InvalidGrant,
			StatusCode: http.StatusBadRequest,
		}
	}
	if flow.IssuerID != i.issuerDID.String() {
		return "", openid4vci.Error{
			Err:        errors.New("pre-authorized code not issued by this issuer"),
			Code:       openid4vci.InvalidGrant,
			StatusCode: http.StatusBadRequest,
		}
	}
	accessToken := crypto.GenerateNonce()
	err = i.store.StoreReference(ctx, flow.ID, accessTokenRefType, accessToken)
	if err != nil {
		return "", err
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
	return accessToken, nil
}

func (i *openidHandler) OfferCredential(ctx context.Context, credential vc.VerifiableCredential, walletIdentifier string) error {
	preAuthorizedCode := crypto.GenerateNonce()
	walletMetadataURL := core.JoinURLPaths(walletIdentifier, openid4vci.WalletMetadataWellKnownPath)
	log.Logger().
		WithField(core.LogFieldCredentialID, credential.ID).
		Infof("Offering credential using OpenID4VCI (client-metadata-url=%s)", walletMetadataURL)

	client, err := i.walletClientCreator(ctx, i.httpClient, walletMetadataURL)
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
	// v1.0 Section 8.2 allows credential_configuration_id, credential_identifier, or format-based requests.
	// This implementation only accepts credential_configuration_id as a policy choice.
	if request.CredentialConfigurationId == "" {
		return nil, openid4vci.Error{
			Err:        errors.New("credential request must contain credential_configuration_id"),
			Code:       openid4vci.InvalidCredentialRequest,
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
			StatusCode: http.StatusUnauthorized,
		}
	}

	credential := flow.Credentials[0] // there's always just one (at least for now)
	subjectDID, _ := credential.SubjectDID()

	if credential.Issuer.String() != i.issuerDID.String() {
		return nil, openid4vci.Error{
			Err:        errors.New("credential issuer does not match given issuer"),
			Code:       openid4vci.InvalidCredentialRequest,
			StatusCode: http.StatusBadRequest,
		}
	}

	// Validate the credential_configuration_id matches what was offered
	expectedConfigID, err := i.findCredentialConfigID(credential)
	if err != nil {
		return nil, openid4vci.Error{
			Err:        fmt.Errorf("credential has no matching configuration: %w", err),
			Code:       openid4vci.UnknownCredentialConfiguration,
			StatusCode: http.StatusBadRequest,
		}
	}
	if request.CredentialConfigurationId != expectedConfigID {
		return nil, openid4vci.Error{
			Err:        fmt.Errorf("credential_configuration_id '%s' does not match offered '%s'", request.CredentialConfigurationId, expectedConfigID),
			Code:       openid4vci.UnknownCredentialConfiguration,
			StatusCode: http.StatusBadRequest,
		}
	}

	if err = i.validateProof(ctx, flow, request); err != nil {
		return nil, err
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

func (i *openidHandler) HandleNonceRequest(ctx context.Context) (string, error) {
	nonce := crypto.GenerateNonce()
	if err := i.store.StoreNonce(ctx, nonce); err != nil {
		return "", err
	}
	return nonce, nil
}

// validateProof validates the proof of the credential request. Aside from checks as specified by the spec,
// it verifies the proof signature, and whether the signer is the intended wallet.
// The validation is metadata-driven: proof is only required if the credential configuration
// includes proof_types_supported. Nonce is only required if the issuer advertises a nonce_endpoint.
// See https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-proof-types
func (i *openidHandler) validateProof(ctx context.Context, flow *Flow, request openid4vci.CredentialRequest) error {
	// Check if the credential configuration requires proof
	credConfig, ok := i.credentialConfigurationsSupported[request.CredentialConfigurationId]
	if ok {
		if _, hasProofTypes := credConfig["proof_types_supported"]; !hasProofTypes {
			return nil // no proof required for this credential configuration
		}
	}

	credential := flow.Credentials[0] // there's always just one (at least for now)
	wallet, _ := credential.SubjectDID()

	if request.Proofs == nil || len(request.Proofs.Jwt) == 0 {
		return openid4vci.Error{
			Err:        errors.New("missing proofs"),
			Code:       openid4vci.InvalidProof,
			StatusCode: http.StatusBadRequest,
		}
	}
	// We only support single proof for now
	proofJWT := request.Proofs.Jwt[0]
	var signingKeyID string
	token, err := crypto.ParseJWT(proofJWT, func(kid string) (crypt.PublicKey, error) {
		signingKeyID = kid
		return i.keyResolver.ResolveKeyByID(kid, nil, resolver.NutsSigningKeyType)
	}, openID4VCIProofProfile, nil)
	if err != nil {
		return openid4vci.Error{
			Err:        err,
			Code:       openid4vci.InvalidProof,
			StatusCode: http.StatusBadRequest,
		}
	}

	// Proof must be signed by wallet to which it was offered (proof signer == offer receiver)
	if signerDID, err := resolver.GetDIDFromURL(signingKeyID); err != nil || signerDID.String() != wallet.String() {
		return openid4vci.Error{
			Err:        fmt.Errorf("credential offer was signed by other DID than intended wallet: %s", signingKeyID),
			Code:       openid4vci.InvalidProof,
			StatusCode: http.StatusBadRequest,
		}
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
		return openid4vci.Error{
			Err:        fmt.Errorf("audience doesn't match credential issuer (aud=%s)", token.Audience()),
			Code:       openid4vci.InvalidProof,
			StatusCode: http.StatusBadRequest,
		}
	}

	// Validate JWT type
	// jwt.Parse does not provide the JWS headers, we have to parse it again as JWS to access those
	message, err := jws.ParseString(proofJWT)
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
		return openid4vci.Error{
			Err:        errors.New("missing typ header"),
			Code:       openid4vci.InvalidProof,
			StatusCode: http.StatusBadRequest,
		}
	}
	if typ != openid4vci.JWTTypeOpenID4VCIProof {
		return openid4vci.Error{
			Err:        fmt.Errorf("invalid typ claim (expected: %s): %s", openid4vci.JWTTypeOpenID4VCIProof, typ),
			Code:       openid4vci.InvalidProof,
			StatusCode: http.StatusBadRequest,
		}
	}

	// Nonce validation: only required if the issuer advertises a nonce_endpoint
	metadata := i.Metadata()
	if metadata.NonceEndpoint == "" {
		return nil // no nonce required
	}


	// given the JWT typ, the nonce is in the 'nonce' claim
	nonce, ok := token.Get("nonce")
	if !ok {
		return openid4vci.Error{
			Err:        errors.New("missing nonce claim"),
			Code:       openid4vci.InvalidProof,
			StatusCode: http.StatusBadRequest,
		}
	}

	nonceValue, ok := nonce.(string)
	if !ok {
		return openid4vci.Error{
			Err:        errors.New("nonce claim is not a string"),
			Code:       openid4vci.InvalidProof,
			StatusCode: http.StatusBadRequest,
		}
	}

	// Validate nonce from Nonce Endpoint (v1.0 Section 7)
	if i.store.ConsumeNonce(ctx, nonceValue) {
		return nil
	}

	return openid4vci.Error{
		Err:        errors.New("invalid or expired nonce"),
		Code:       openid4vci.InvalidNonce,
		StatusCode: http.StatusBadRequest,
	}
}

func (i *openidHandler) createOffer(ctx context.Context, credential vc.VerifiableCredential, preAuthorizedCode string) (*openid4vci.CredentialOffer, error) {
	credentialConfigID, err := i.findCredentialConfigID(credential)
	if err != nil {
		return nil, fmt.Errorf("unable to create credential offer: %w", err)
	}

	offer := openid4vci.CredentialOffer{
		CredentialIssuer:           i.issuerIdentifierURL,
		CredentialConfigurationIds: []string{credentialConfigID},
		Grants: openid4vci.CredentialOfferGrants{
			PreAuthorizedCode: &openid4vci.PreAuthorizedCodeParams{
				PreAuthorizedCode: preAuthorizedCode,
			},
		},
	}
	subjectDID, _ := credential.SubjectDID() // succeeded in previous step, can't fail

	flow := Flow{
		ID:          uuid.NewString(),
		IssuerID:    credential.Issuer.String(),
		WalletID:    subjectDID.String(),
		Credentials: []vc.VerifiableCredential{credential},
		Grants: []Grant{
			{
				Type: openid4vci.PreAuthorizedCodeGrant,
				Params: map[string]interface{}{
					"pre-authorized_code": preAuthorizedCode,
				},
			},
		},
	}
	err = i.store.Store(ctx, flow)
	if err == nil {
		err = i.store.StoreReference(ctx, flow.ID, preAuthCodeRefType, preAuthorizedCode)
	}
	if err != nil {
		return nil, fmt.Errorf("unable to store credential offer: %w", err)
	}
	return &offer, nil
}

func (i *openidHandler) loadCredentialDefinitions() error {
	i.credentialConfigurationsSupported = make(map[string]map[string]interface{})

	addDefinition := func(source string, definitionMap map[string]interface{}) error {
		configID, err := generateCredentialConfigID(definitionMap)
		if err != nil {
			return fmt.Errorf("invalid credential definition from %s: %w", source, err)
		}
		if _, exists := i.credentialConfigurationsSupported[configID]; exists {
			return fmt.Errorf("duplicate credential_configuration_id '%s' from %s", configID, source)
		}
		i.credentialConfigurationsSupported[configID] = definitionMap
		return nil
	}

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
		if err := addDefinition("assets/"+definition.Name(), definitionMap); err != nil {
			return err
		}
	}

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
				if err := addDefinition(path, definitionMap); err != nil {
					return err
				}
			}
			return nil
		})
	}

	return err
}

func deepcopyMap(src map[string]map[string]interface{}) map[string]map[string]interface{} {
	// Safe to ignore errors: src is always built from JSON-deserialized data.
	data, err := json.Marshal(src)
	if err != nil {
		panic("deepcopyMap: marshal failed: " + err.Error())
	}
	var dst map[string]map[string]interface{}
	if err = json.Unmarshal(data, &dst); err != nil {
		panic("deepcopyMap: unmarshal failed: " + err.Error())
	}
	return dst
}

// generateCredentialConfigID generates a credential_configuration_id from a credential definition.
// The ID is formed as "{MostSpecificType}_{format}" (e.g., "NutsOrganizationCredential_ldp_vc").
// Returns an error if the definition is missing required fields to generate a unique ID.
func generateCredentialConfigID(definitionMap map[string]interface{}) (string, error) {
	format, _ := definitionMap["format"].(string)
	if format == "" {
		return "", errors.New("credential definition missing 'format' field")
	}
	credDef, ok := definitionMap["credential_definition"].(map[string]interface{})
	if !ok {
		return "", errors.New("credential definition missing 'credential_definition' field")
	}

	types, ok := credDef["type"].([]interface{})
	if !ok || len(types) == 0 {
		return "", errors.New("credential definition missing 'type' field")
	}

	// Find the most specific type (typically the last one, excluding VerifiableCredential)
	var specificType string
	for _, t := range types {
		if typeStr, ok := t.(string); ok && typeStr != "VerifiableCredential" {
			specificType = typeStr
		}
	}
	if specificType == "" {
		specificType = "VerifiableCredential"
	}

	return specificType + "_" + format, nil
}

// findCredentialConfigID finds the credential configuration ID for the given credential
// by matching it against the loaded credential_configurations_supported.
// Returns an error if no matching configuration is found, since credential_configuration_ids
// in offers MUST reference entries in credential_configurations_supported (Section 4.1.1).
func (i *openidHandler) findCredentialConfigID(credential vc.VerifiableCredential) (string, error) {
	for configID, config := range i.credentialConfigurationsSupported {
		if matchesCredential(config, credential) {
			return configID, nil
		}
	}
	return "", fmt.Errorf("no matching credential configuration for type %s", credential.Type)
}

// matchesCredential checks if a credential configuration matches the given credential
// by comparing format, type, and @context.
// Type matching is exact (count must be equal). Context matching is a subset check:
// all config contexts must appear in the credential, but the credential may have additional
// contexts (e.g., proof-related contexts added during signing).
func matchesCredential(config map[string]interface{}, credential vc.VerifiableCredential) bool {
	format, _ := config["format"].(string)
	if format != vc.JSONLDCredentialProofFormat {
		return false
	}

	credDef, ok := config["credential_definition"].(map[string]interface{})
	if !ok {
		return false
	}

	types, ok := credDef["type"].([]interface{})
	if !ok {
		return false
	}
	if len(types) != len(credential.Type) {
		return false
	}
	for _, configType := range types {
		typeStr, ok := configType.(string)
		if !ok {
			continue
		}
		found := false
		for _, credType := range credential.Type {
			if credType.String() == typeStr {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	contexts, ok := credDef["@context"].([]interface{})
	if !ok {
		return false
	}
	for _, configCtx := range contexts {
		ctxStr, ok := configCtx.(string)
		if !ok {
			continue
		}
		found := false
		for _, credCtx := range credential.Context {
			if credCtx.String() == ctxStr {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	return true
}

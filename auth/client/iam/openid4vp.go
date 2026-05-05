/*
 * Nuts node
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
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/nuts-foundation/nuts-node/http/client"
	"github.com/nuts-foundation/nuts-node/policy"
	"github.com/nuts-foundation/nuts-node/vcr/credential"
	"github.com/nuts-foundation/nuts-node/vdr/didsubject"
	"github.com/piprate/json-gold/ld"
	"maps"
	"net/http"
	"net/url"
	"slices"
	"time"

	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/auth/log"
	"github.com/nuts-foundation/nuts-node/auth/oauth"
	"github.com/nuts-foundation/nuts-node/core"
	nutsCrypto "github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/crypto/dpop"
	nutsHttp "github.com/nuts-foundation/nuts-node/http"
	"github.com/nuts-foundation/nuts-node/vcr/holder"
	"github.com/nuts-foundation/nuts-node/vcr/pe"
	"github.com/nuts-foundation/nuts-node/vdr/resolver"
)

// ErrPreconditionFailed is returned when a precondition is not met.
var ErrPreconditionFailed = errors.New("precondition failed")

// vpAssertionLifetime is the validity window of a Verifiable Presentation built for a token request.
// Short by design: the VP is signed and posted within the same call.
const vpAssertionLifetime = 5 * time.Second

var _ Client = (*OpenID4VPClient)(nil)

type OpenID4VPClient struct {
	httpClient                  HTTPClient
	jwtSigner                   nutsCrypto.JWTSigner
	keyResolver                 resolver.KeyResolver
	strictMode                  bool
	wallet                      holder.Wallet
	ldDocumentLoader            ld.DocumentLoader
	subjectManager              didsubject.Manager
	pdResolver                  PresentationDefinitionResolver
	policyBackend               policy.PDPBackend
	experimentalJwtBearerClient bool
}

// ClientConfig groups the dependencies and toggles needed to construct an OpenID4VPClient.
// The interface fields (Wallet, KeyResolver, SubjectManager, JWTSigner, LDDocumentLoader,
// PolicyBackend) are required; NewClient does not validate them and missing fields will surface as
// nil-pointer panics on first use. Scalar fields default to their zero value (StrictMode=false,
// HTTPClientTimeout=0, ExperimentalJwtBearerClient=false) and the zero values are valid.
type ClientConfig struct {
	Wallet            holder.Wallet
	KeyResolver       resolver.KeyResolver
	SubjectManager    didsubject.Manager
	JWTSigner         nutsCrypto.JWTSigner
	LDDocumentLoader  ld.DocumentLoader
	PolicyBackend     policy.PDPBackend
	StrictMode        bool
	HTTPClientTimeout time.Duration
	// ExperimentalJwtBearerClient gates the RFC 7523 jwt-bearer two-VP token request flow.
	// Tracked for replacement by a list-style grant-types config under issue #4231.
	ExperimentalJwtBearerClient bool
}

// NewClient returns an OpenID4VPClient configured with the given dependencies.
func NewClient(cfg ClientConfig) *OpenID4VPClient {
	httpClient := HTTPClient{
		strictMode:  cfg.StrictMode,
		httpClient:  client.NewWithCache(cfg.HTTPClientTimeout),
		keyResolver: cfg.KeyResolver,
	}
	c := &OpenID4VPClient{
		httpClient:                  httpClient,
		keyResolver:                 cfg.KeyResolver,
		jwtSigner:                   cfg.JWTSigner,
		ldDocumentLoader:            cfg.LDDocumentLoader,
		subjectManager:              cfg.SubjectManager,
		strictMode:                  cfg.StrictMode,
		wallet:                      cfg.Wallet,
		policyBackend:               cfg.PolicyBackend,
		experimentalJwtBearerClient: cfg.ExperimentalJwtBearerClient,
	}
	c.pdResolver = PresentationDefinitionResolver{
		pdFetcher:     c,
		policyBackend: cfg.PolicyBackend,
	}
	return c
}

func (c *OpenID4VPClient) ClientMetadata(ctx context.Context, endpoint string) (*oauth.OAuthClientMetadata, error) {
	iamClient := c.httpClient

	metadata, err := iamClient.ClientMetadata(ctx, endpoint)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve OAuth client metadata: %w", err)
	}
	return metadata, nil
}

func (c *OpenID4VPClient) PostError(ctx context.Context, auth2Error oauth.OAuth2Error, verifierResponseURI string, verifierClientState string) (string, error) {
	iamClient := c.httpClient

	responseURL, err := core.ParsePublicURL(verifierResponseURI, c.strictMode)
	if err != nil {
		return "", fmt.Errorf("failed to post error to verifier: %w", err)
	}
	validURL := *responseURL
	if verifierClientState != "" {
		validURL = nutsHttp.AddQueryParams(*responseURL, map[string]string{
			oauth.StateParam: verifierClientState,
		})
	}
	redirectURL, err := iamClient.PostError(ctx, auth2Error, validURL)
	if err != nil {
		return "", fmt.Errorf("failed to post error to verifier: %w", err)
	}

	return redirectURL, nil
}

func (c *OpenID4VPClient) PostAuthorizationResponse(ctx context.Context, vp vc.VerifiablePresentation, presentationSubmission pe.PresentationSubmission, verifierResponseURI string, state string) (string, error) {
	iamClient := c.httpClient

	responseURL, err := core.ParsePublicURL(verifierResponseURI, c.strictMode)
	if err != nil {
		return "", fmt.Errorf("failed to post error to verifier: %w", err)
	}
	redirectURL, err := iamClient.PostAuthorizationResponse(ctx, vp, presentationSubmission, *responseURL, state)
	if err == nil {
		return redirectURL, nil
	}

	return "", fmt.Errorf("failed to post authorization response to verifier: %w", err)
}

func (c *OpenID4VPClient) PresentationDefinition(ctx context.Context, endpoint string) (*pe.PresentationDefinition, error) {
	iamClient := c.httpClient
	parsedURL, err := core.ParsePublicURL(endpoint, c.strictMode)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve presentation definition: %w", err)
	}
	presentationDefinition, err := iamClient.PresentationDefinition(ctx, *parsedURL)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve presentation definition: %w", err)
	}
	return presentationDefinition, nil
}

func (c *OpenID4VPClient) AuthorizationServerMetadata(ctx context.Context, oauthIssuer string) (*oauth.AuthorizationServerMetadata, error) {
	iamClient := c.httpClient
	// the wallet/client acts as authorization server
	metadata, err := iamClient.OAuthAuthorizationServerMetadata(ctx, oauthIssuer)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve remote OAuth Authorization Server metadata: %w", err)
	}
	return metadata, nil
}

func (c *OpenID4VPClient) OpenIDConfiguration(ctx context.Context, issuer string) (*oauth.OpenIDConfiguration, error) {
	iamClient := c.httpClient
	// the wallet/client acts as authorization server
	metadata, err := iamClient.OpenIDConfiguration(ctx, issuer)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve remote OpenID configuration: %w", err)
	}
	return metadata, nil
}

func (c *OpenID4VPClient) RequestObjectByGet(ctx context.Context, requestURI string) (string, error) {
	iamClient := c.httpClient
	parsedURL, err := core.ParsePublicURL(requestURI, c.strictMode)
	if err != nil {
		return "", fmt.Errorf("invalid request_uri: %w", err)
	}

	requestObject, err := iamClient.RequestObjectByGet(ctx, parsedURL.String())
	if err != nil {
		return "", fmt.Errorf("failed to retrieve JAR Request Object: %w", err)
	}
	return requestObject, nil
}
func (c *OpenID4VPClient) RequestObjectByPost(ctx context.Context, requestURI string, walletMetadata oauth.AuthorizationServerMetadata) (string, error) {
	iamClient := c.httpClient
	parsedURL, err := core.ParsePublicURL(requestURI, c.strictMode)
	if err != nil {
		return "", fmt.Errorf("invalid request_uri: %w", err)
	}

	// TODO: consider adding a 'wallet_nonce'
	metadataBytes, _ := json.Marshal(walletMetadata)
	form := url.Values{oauth.WalletMetadataParam: {string(metadataBytes)}}
	requestObject, err := iamClient.RequestObjectByPost(ctx, parsedURL.String(), form)
	if err != nil {
		return "", fmt.Errorf("failed to retrieve JAR Request Object: %w", err)
	}
	return requestObject, nil
}

func (c *OpenID4VPClient) AccessToken(ctx context.Context, code string, tokenEndpoint string, callbackURI string, subject string, clientID string, codeVerifier string, useDPoP bool) (*oauth.TokenResponse, error) {
	iamClient := c.httpClient
	// validate tokenEndpoint
	parsedURL, err := core.ParsePublicURL(tokenEndpoint, c.strictMode)
	if err != nil {
		return nil, err
	}

	// call token endpoint
	data := url.Values{}
	data.Set(oauth.ClientIDParam, clientID)
	data.Set(oauth.GrantTypeParam, oauth.AuthorizationCodeGrantType)
	data.Set(oauth.CodeParam, code)
	data.Set(oauth.RedirectURIParam, callbackURI)
	data.Set(oauth.CodeVerifierParam, codeVerifier)

	var dpopHeader string
	var dpopKid string
	if useDPoP {
		// create DPoP header
		request, err := http.NewRequestWithContext(ctx, http.MethodPost, parsedURL.String(), nil)
		if err != nil {
			return nil, err
		}
		dids, err := c.subjectManager.ListDIDs(ctx, subject)
		if err != nil {
			return nil, err
		}
		// todo select the right DID based upon metadata
		dpopHeader, dpopKid, err = c.dpop(ctx, dids[0], *request)
		if err != nil {
			return nil, fmt.Errorf("failed to create DPoP header: %w", err)
		}
	}

	token, err := iamClient.AccessToken(ctx, parsedURL.String(), data, dpopHeader)
	if err != nil {
		return nil, fmt.Errorf("remote server: error creating access token: %w", err)
	}
	if dpopKid != "" {
		token.DPoPKid = &dpopKid
	}
	return &token, nil
}

func (c *OpenID4VPClient) RequestServiceAccessToken(ctx context.Context, clientID string, subjectID string, authServerURL string, scopes string,
	useDPoP bool, additionalCredentials []vc.VerifiableCredential, credentialSelection map[string]string, serviceProviderSubjectID *string) (*oauth.TokenResponse, error) {
	if serviceProviderSubjectID != nil && !c.experimentalJwtBearerClient {
		return nil, oauth.OAuth2Error{
			Code:        oauth.UnsupportedGrantType,
			Description: "jwt-bearer two-VP flow requires auth.experimental.jwt_bearer_client = true",
		}
	}
	metadata, err := c.AuthorizationServerMetadata(ctx, authServerURL)
	if err != nil {
		return nil, err
	}
	if serviceProviderSubjectID != nil {
		if !slices.Contains(metadata.GrantTypesSupported, oauth.JwtBearerGrantType) {
			return nil, oauth.OAuth2Error{
				Code:        oauth.UnsupportedGrantType,
				Description: fmt.Sprintf("authorization server does not advertise %q in grant_types_supported", oauth.JwtBearerGrantType),
			}
		}
		return c.requestJwtBearerAccessToken(ctx, subjectID, *serviceProviderSubjectID, authServerURL, scopes, useDPoP, additionalCredentials, credentialSelection, metadata)
	}
	return c.requestVPTokenAccessToken(ctx, clientID, subjectID, authServerURL, scopes, useDPoP, additionalCredentials, credentialSelection, metadata)
}

// requestVPTokenAccessToken implements the single-VP RFC021 vp_token-bearer flow: resolve the
// presentation definition (remotely if the AS advertises one, locally otherwise), build a single VP from
// the caller's wallet, and POST it as `assertion` alongside the PE submission and DPoP header (when used).
func (c *OpenID4VPClient) requestVPTokenAccessToken(ctx context.Context, clientID string, subjectID string, authServerURL string,
	scopes string, useDPoP bool, additionalCredentials []vc.VerifiableCredential, credentialSelection map[string]string,
	metadata *oauth.AuthorizationServerMetadata) (*oauth.TokenResponse, error) {
	// Resolve the presentation definition: from remote AS when available, local policy otherwise
	resolved, err := c.pdResolver.Resolve(ctx, scopes, *metadata)
	if err != nil {
		return nil, err
	}
	presentationDefinition := &resolved.PresentationDefinition

	params := holder.BuildParams{
		Audience:   authServerURL,
		DIDMethods: metadata.DIDMethodsSupported,
		Expires:    time.Now().Add(vpAssertionLifetime),
		Format:     metadata.VPFormatsSupported,
		Nonce:      nutsCrypto.GenerateNonce(),
	}

	vp, submission, err := c.buildSubmissionForSubject(ctx, subjectID, *presentationDefinition, additionalCredentials, credentialSelection, params)
	if err != nil {
		return nil, err
	}
	subjectDID, err := did.ParseDID(vp.Holder.String())
	if err != nil {
		return nil, err
	}

	assertion := vp.Raw()
	presentationSubmission, _ := json.Marshal(submission)
	data := url.Values{}
	data.Set(oauth.ClientIDParam, clientID)
	data.Set(oauth.GrantTypeParam, oauth.VpTokenGrantType)
	data.Set(oauth.AssertionParam, assertion)
	data.Set(oauth.PresentationSubmissionParam, string(presentationSubmission))
	data.Set(oauth.ScopeParam, resolved.Scope)

	dpopHeader, dpopKid, err := c.signDPoPHeader(ctx, useDPoP, *subjectDID, metadata.TokenEndpoint)
	if err != nil {
		return nil, err
	}

	log.Logger().Tracef("Requesting access token from '%s' for scope '%s'\n  VP: %s\n  Submission: %s", metadata.TokenEndpoint, scopes, assertion, string(presentationSubmission))
	token, err := c.httpClient.AccessToken(ctx, metadata.TokenEndpoint, data, dpopHeader)
	if err != nil {
		// the error could be a http error, we just relay it here to make use of any 400 status codes.
		return nil, err
	}
	tokenResponse := oauth.TokenResponse{
		AccessToken: token.AccessToken,
		ExpiresIn:   token.ExpiresIn,
		TokenType:   token.TokenType,
		Scope:       &resolved.Scope,
	}
	if dpopKid != "" {
		tokenResponse.DPoPKid = &dpopKid
	}
	return &tokenResponse, nil
}

// requestJwtBearerAccessToken implements the RFC 7523 jwt-bearer two-VP token request flow.
// It builds VP1 from the healthcare-provider (HCP) wallet using the organization PD, and VP2 from the
// service-provider (SP) wallet using the service_provider PD, assembles them as `assertion` and
// `client_assertion`, and POSTs the token request.
// Per RFC 7521 §4.2 the client is authenticated by the client_assertion, so no OAuth client_id form
// parameter is sent on this path.
// Both PDs are resolved from the local policy backend; the AS's remote presentation_definition endpoint
// is not consulted (no standardised mechanism exists today for the AS to advertise a service_provider PD).
func (c *OpenID4VPClient) requestJwtBearerAccessToken(ctx context.Context, organizationSubjectID string, serviceProviderSubjectID string,
	authServerURL string, scopes string, useDPoP bool, additionalCredentials []vc.VerifiableCredential, credentialSelection map[string]string,
	metadata *oauth.AuthorizationServerMetadata) (*oauth.TokenResponse, error) {
	profile, resolvedScope, err := loadAndValidateProfile(ctx, c.policyBackend, scopes)
	if err != nil {
		return nil, err
	}
	// loadAndValidateProfile guarantees the organization PD; the service_provider PD is two-VP-specific.
	orgPD := profile.WalletOwnerMapping[pe.WalletOwnerOrganization]
	spPD, hasSP := profile.WalletOwnerMapping[pe.WalletOwnerServiceProvider]
	if !hasSP {
		return nil, oauth.OAuth2Error{
			Code:        oauth.InvalidScope,
			Description: fmt.Sprintf("no service_provider presentation definition for scope %q", profile.CredentialProfileScope),
		}
	}
	params := holder.BuildParams{
		Audience:   authServerURL,
		DIDMethods: metadata.DIDMethodsSupported,
		Expires:    time.Now().Add(vpAssertionLifetime),
		Format:     metadata.VPFormatsSupported,
		Nonce:      nutsCrypto.GenerateNonce(),
	}
	organizationVP, organizationSubmission, err := c.buildSubmissionForSubject(ctx, organizationSubjectID, orgPD, additionalCredentials, credentialSelection, params)
	if err != nil {
		return nil, err
	}
	// Cross-VP binding: capture id-bearing constraint field values resolved against the organization VP
	// and additively merge them into the credential_selection map for the service-provider VP. The
	// submission tells us which credential satisfied each input descriptor; we use that to walk the PD's
	// id-bearing fields and extract their matched values.
	envelope, err := pe.NewEnvelopeFromVP(*organizationVP)
	if err != nil {
		return nil, oauth.OAuth2Error{
			Code:        oauth.ServerError,
			Description: fmt.Sprintf("failed to wrap the organization VP in an envelope for cross-VP binding: %s", err),
		}
	}
	credentialMap, err := organizationSubmission.Resolve(*envelope)
	if err != nil {
		return nil, oauth.OAuth2Error{
			Code:        oauth.ServerError,
			Description: fmt.Sprintf("failed to resolve the organization VP submission for cross-VP binding: %s", err),
		}
	}
	captured, err := orgPD.ResolveConstraintsFields(credentialMap)
	if err != nil {
		return nil, oauth.OAuth2Error{
			Code:        oauth.ServerError,
			Description: fmt.Sprintf("failed to extract cross-VP binding values from the organization VP against the organization presentation definition: %s", err),
		}
	}
	credentialSelection = applyCapturedFieldsToSelection(credentialSelection, captured)
	// Each VP must carry its own nonce; reuse would let a verifier confuse the two assertions.
	params.Nonce = nutsCrypto.GenerateNonce()
	serviceProviderVP, _, err := c.buildSubmissionForSubject(ctx, serviceProviderSubjectID, spPD, additionalCredentials, credentialSelection, params)
	if err != nil {
		return nil, err
	}
	// DPoP binds the issued access token to a key the service provider controls — the SP wallet will
	// present and use the token, so the proof is signed with the SP DID's key.
	spDID, err := did.ParseDID(serviceProviderVP.Holder.String())
	if err != nil {
		return nil, err
	}
	dpopHeader, dpopKid, err := c.signDPoPHeader(ctx, useDPoP, *spDID, metadata.TokenEndpoint)
	if err != nil {
		return nil, err
	}
	data := url.Values{}
	data.Set(oauth.GrantTypeParam, oauth.JwtBearerGrantType)
	data.Set(oauth.AssertionParam, organizationVP.Raw())
	data.Set(oauth.ClientAssertionTypeParam, oauth.JwtBearerClientAssertionType)
	data.Set(oauth.ClientAssertionParam, serviceProviderVP.Raw())
	data.Set(oauth.ScopeParam, resolvedScope)

	log.Logger().Tracef("Requesting jwt-bearer access token from '%s' for scope '%s'\n  organization VP: %s\n  service provider VP: %s", metadata.TokenEndpoint, resolvedScope, organizationVP.Raw(), serviceProviderVP.Raw())
	token, err := c.httpClient.AccessToken(ctx, metadata.TokenEndpoint, data, dpopHeader)
	if err != nil {
		return nil, err
	}
	tokenResponse := oauth.TokenResponse{
		AccessToken: token.AccessToken,
		ExpiresIn:   token.ExpiresIn,
		TokenType:   token.TokenType,
		Scope:       &resolvedScope,
	}
	if dpopKid != "" {
		tokenResponse.DPoPKid = &dpopKid
	}
	return &tokenResponse, nil
}

// buildSubmissionForSubject lists DIDs for the given subject, filters them to those whose method is in
// params.DIDMethods, and asks the wallet to build a VP that fulfills the given PresentationDefinition.
func (c *OpenID4VPClient) buildSubmissionForSubject(ctx context.Context, subjectID string, presentationDefinition pe.PresentationDefinition,
	additionalCredentials []vc.VerifiableCredential, credentialSelection map[string]string, params holder.BuildParams) (*vc.VerifiablePresentation, *pe.PresentationSubmission, error) {
	subjectDIDs, err := c.subjectManager.ListDIDs(ctx, subjectID)
	if err != nil {
		return nil, nil, err
	}
	subjectDIDs, err = filterDIDsByMethods(subjectDIDs, params.DIDMethods)
	if err != nil {
		return nil, nil, err
	}
	additionalWalletCredentials := map[did.DID][]vc.VerifiableCredential{}
	for _, subjectDID := range subjectDIDs {
		for _, curr := range additionalCredentials {
			additionalWalletCredentials[subjectDID] = append(additionalWalletCredentials[subjectDID], credential.AutoCorrectSelfAttestedCredential(curr, subjectDID))
		}
	}
	return c.wallet.BuildSubmission(ctx, subjectDIDs, additionalWalletCredentials, presentationDefinition, credentialSelection, params)
}

// applyCapturedFieldsToSelection returns a fresh selection map containing every entry from selection
// plus any string-valued entry from captured whose key is not already present. Non-string captured values
// are skipped (selection is map[string]string). The caller's selection map is never mutated, so the
// captured values cannot leak back through any retained reference.
func applyCapturedFieldsToSelection(selection map[string]string, captured map[string]any) map[string]string {
	merged := make(map[string]string, len(selection)+len(captured))
	for k, v := range selection {
		merged[k] = v
	}
	for k, v := range captured {
		if _, exists := merged[k]; exists {
			continue
		}
		s, ok := v.(string)
		if !ok {
			continue
		}
		merged[k] = s
	}
	return merged
}

// filterDIDsByMethods drops DIDs whose method is not in supportedMethods. Returns ErrPreconditionFailed when
// none of the subject's DIDs use a supported method.
func filterDIDsByMethods(subjectDIDs []did.DID, supportedMethods []string) ([]did.DID, error) {
	j := 0
	allMethods := map[string]struct{}{}
	for i, d := range subjectDIDs {
		allMethods[d.Method] = struct{}{}
		if slices.Contains(supportedMethods, d.Method) {
			subjectDIDs[j] = subjectDIDs[i]
			j++
		}
	}
	subjectDIDs = subjectDIDs[:j]
	if len(subjectDIDs) == 0 {
		availableMethods := make([]string, 0, len(allMethods))
		for key := range maps.Keys(allMethods) {
			availableMethods = append(availableMethods, key)
		}
		return nil, errors.Join(ErrPreconditionFailed, fmt.Errorf("did method mismatch, requested: %v, available: %v", supportedMethods, availableMethods))
	}
	return subjectDIDs, nil
}

func (c *OpenID4VPClient) OpenIdCredentialIssuerMetadata(ctx context.Context, oauthIssuerURI string) (*oauth.OpenIDCredentialIssuerMetadata, error) {
	iamClient := c.httpClient
	rsp, err := iamClient.OpenIdCredentialIssuerMetadata(ctx, oauthIssuerURI)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve Openid credential issuer metadata: %w", err)
	}
	return rsp, nil
}

func (c *OpenID4VPClient) VerifiableCredentials(ctx context.Context, credentialEndpoint string, accessToken string, proofJWT string) (*CredentialResponse, error) {
	iamClient := c.httpClient
	rsp, err := iamClient.VerifiableCredentials(ctx, credentialEndpoint, accessToken, proofJWT)
	if err != nil {
		return nil, fmt.Errorf("remote server: failed to retrieve credentials: %w", err)
	}
	return rsp, nil
}

// signDPoPHeader signs a DPoP proof for a token-endpoint POST bound to signerDID's assertion key.
// Returns ("", "", nil) when useDPoP is false so callers can use the result unconditionally.
func (c *OpenID4VPClient) signDPoPHeader(ctx context.Context, useDPoP bool, signerDID did.DID, tokenEndpoint string) (string, string, error) {
	if !useDPoP {
		return "", "", nil
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenEndpoint, nil)
	if err != nil {
		return "", "", err
	}
	header, kid, err := c.dpop(ctx, signerDID, *request)
	if err != nil {
		return "", "", fmt.Errorf("failed to create DPoP header: %w", err)
	}
	return header, kid, nil
}

func (c *OpenID4VPClient) dpop(ctx context.Context, requester did.DID, request http.Request) (string, string, error) {
	// find the key to sign the DPoP token with
	keyID, _, err := c.keyResolver.ResolveKey(requester, nil, resolver.AssertionMethod)
	if err != nil {
		return "", "", err
	}

	token := dpop.New(request)
	jwt, err := c.jwtSigner.SignDPoP(ctx, *token, keyID)
	if err != nil {
		return "", "", err
	}
	return jwt, keyID, nil
}

/*
* Nuts node
* Copyright (C) 2021 Nuts community
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
 */

package oauth

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/auth/api/auth/v1/client"
	"github.com/nuts-foundation/nuts-node/auth/client/iam"
	"github.com/nuts-foundation/nuts-node/auth/oauth"
	"github.com/nuts-foundation/nuts-node/auth/services"
	"github.com/nuts-foundation/nuts-node/core"
	nutsCrypto "github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/didman"
	http2 "github.com/nuts-foundation/nuts-node/http"
	"github.com/nuts-foundation/nuts-node/vcr/credential"
	"github.com/nuts-foundation/nuts-node/vcr/holder"
	"github.com/nuts-foundation/nuts-node/vcr/signature/proof"
	"github.com/nuts-foundation/nuts-node/vdr/resolver"
)

var _ RelyingParty = (*relyingParty)(nil)

type relyingParty struct {
	keyResolver       resolver.KeyResolver
	privateKeyStore   nutsCrypto.KeyStore
	serviceResolver   didman.CompoundServiceResolver
	strictMode        bool
	httpClientTimeout time.Duration
	httpClientTLS     *tls.Config
	wallet            holder.Wallet
}

// NewRelyingParty returns an implementation of RelyingParty
func NewRelyingParty(
	didResolver resolver.DIDResolver, serviceResolver didman.CompoundServiceResolver, privateKeyStore nutsCrypto.KeyStore,
	wallet holder.Wallet, httpClientTimeout time.Duration, httpClientTLS *tls.Config, strictMode bool) RelyingParty {
	return &relyingParty{
		keyResolver:       resolver.DIDKeyResolver{Resolver: didResolver},
		serviceResolver:   serviceResolver,
		privateKeyStore:   privateKeyStore,
		httpClientTimeout: httpClientTimeout,
		httpClientTLS:     httpClientTLS,
		strictMode:        strictMode,
		wallet:            wallet,
	}
}

// CreateJwtGrant creates a JWT Grant from the given CreateJwtGrantRequest
func (s *relyingParty) CreateJwtGrant(ctx context.Context, request services.CreateJwtGrantRequest) (*services.JwtBearerTokenResult, error) {
	requester, err := did.ParseDID(request.Requester)
	if err != nil {
		return nil, err
	}

	// todo add checks for missing values?
	authorizer, err := did.ParseDID(request.Authorizer)
	if err != nil {
		return nil, err
	}

	for _, verifiableCredential := range request.Credentials {
		validator := credential.FindValidator(verifiableCredential)
		if err := validator.Validate(verifiableCredential); err != nil {
			return nil, fmt.Errorf("invalid VerifiableCredential: %w", err)
		}
	}

	endpointURL, err := s.serviceResolver.GetCompoundServiceEndpoint(*authorizer, request.Service, services.OAuthEndpointType, true)
	if err != nil {
		return nil, fmt.Errorf("could not fetch authorizer's 'oauth' endpoint from compound service: %w", err)
	}

	keyVals := claimsFromRequest(request, endpointURL)

	signingKeyID, _, err := s.keyResolver.ResolveKey(*requester, nil, resolver.NutsSigningKeyType)
	if err != nil {
		return nil, err
	}
	signingString, err := s.privateKeyStore.SignJWT(ctx, keyVals, nil, signingKeyID.String())
	if err != nil {
		return nil, err
	}

	return &services.JwtBearerTokenResult{BearerToken: signingString, AuthorizationServerEndpoint: endpointURL}, nil
}

func (s *relyingParty) CreateAuthorizationRequest(ctx context.Context, requestHolder did.DID, verifier did.DID, scopes string, clientState string) (*url.URL, error) {
	// we want to make a call according to §4.1.1 of RFC6749, https://www.rfc-editor.org/rfc/rfc6749.html#section-4.1.1
	// The URL should be listed in the verifier metadata under the "authorization_endpoint" key
	iamClient := iam.NewHTTPClient(s.strictMode, s.httpClientTimeout, s.httpClientTLS)
	metadata, err := iamClient.OAuthAuthorizationServerMetadata(ctx, verifier)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve remote OAuth Authorization Server metadata: %w", err)
	}
	if len(metadata.AuthorizationEndpoint) == 0 {
		return nil, fmt.Errorf("no authorization endpoint found in metadata for %s", verifier)
	}
	endpoint, err := url.Parse(metadata.AuthorizationEndpoint)
	if err != nil {
		return nil, fmt.Errorf("failed to parse authorization endpoint URL: %w", err)
	}
	// todo: redirect_uri
	redirectURL := http2.AddQueryParams(*endpoint, map[string]string{
		"client_id":     requestHolder.String(),
		"response_type": "code",
		"scope":         scopes,
		"state":         clientState,
	})
	return &redirectURL, nil
}

func (s *relyingParty) RequestRFC003AccessToken(ctx context.Context, jwtGrantToken string, authorizationServerEndpoint url.URL) (*oauth.TokenResponse, error) {
	if s.strictMode && strings.ToLower(authorizationServerEndpoint.Scheme) != "https" {
		return nil, fmt.Errorf("authorization server endpoint must be HTTPS when in strict mode: %s", authorizationServerEndpoint.String())
	}
	httpClient := &http.Client{}
	if s.httpClientTLS != nil {
		httpClient.Transport = &http.Transport{
			TLSClientConfig: s.httpClientTLS,
		}
	}
	authClient, err := client.NewHTTPClient("", s.httpClientTimeout, client.WithHTTPClient(httpClient), client.WithRequestEditorFn(core.UserAgentRequestEditor))
	if err != nil {
		return nil, fmt.Errorf("unable to create HTTP client: %w", err)
	}
	accessTokenResponse, err := authClient.CreateAccessToken(ctx, authorizationServerEndpoint, jwtGrantToken)
	if err != nil {
		return nil, fmt.Errorf("remote server/nuts node returned error creating access token: %w", err)
	}
	return accessTokenResponse, nil
}

func (s *relyingParty) RequestRFC021AccessToken(ctx context.Context, requester did.DID, verifier did.DID, scopes string) (*oauth.TokenResponse, error) {
	iamClient := iam.NewHTTPClient(s.strictMode, s.httpClientTimeout, s.httpClientTLS)
	metadata, err := s.AuthorizationServerMetadata(ctx, verifier)
	if err != nil {
		return nil, err
	}

	// get the presentation definition from the verifier
	presentationDefinition, err := iamClient.PresentationDefinition(ctx, metadata.PresentationDefinitionEndpoint, scopes)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve presentation definition: %w", err)
	}

	walletCredentials, err := s.wallet.List(ctx, requester)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve wallet credentials: %w", err)
	}

	// match against the wallet's credentials
	// if there's a match, create a VP and call the token endpoint
	// If the token endpoint succeeds, return the access token
	// If no presentation definition matches, return a 412 "no matching credentials" error
	builder := presentationDefinition.PresentationSubmissionBuilder()
	builder.AddWallet(requester, walletCredentials)

	// Find supported VP format, matching support from:
	// - what the local Nuts node supports
	// - the presentation definition "claimed format designation" (optional)
	// - the verifier's metadata (optional)
	formatCandidates := credential.OpenIDSupportedFormats(oauth.DefaultOpenIDSupportedFormats())
	if metadata.VPFormats != nil {
		formatCandidates = formatCandidates.Match(credential.OpenIDSupportedFormats(metadata.VPFormats))
	}
	if presentationDefinition.Format != nil {
		formatCandidates = formatCandidates.Match(credential.DIFClaimFormats(*presentationDefinition.Format))
	}
	format := chooseVPFormat(formatCandidates.Map)
	if format == "" {
		return nil, errors.New("requester, verifier (authorization server metadata) and presentation definition don't share a supported VP format")
	}
	// TODO: format parameters (alg, proof_type, etc.) are ignored, but should be used in the actual signing
	submission, signInstructions, err := builder.Build(format)
	if err != nil {
		return nil, fmt.Errorf("failed to match presentation definition: %w", err)
	}
	if signInstructions.Empty() {
		return nil, core.Error(http.StatusPreconditionFailed, "no matching credentials")
	}
	expires := time.Now().Add(time.Second * 5)
	// todo: support multiple wallets
	domain := verifier.String()
	nonce := nutsCrypto.GenerateNonce()
	vp, err := s.wallet.BuildPresentation(ctx, signInstructions[0].VerifiableCredentials, holder.PresentationOptions{
		Format: format,
		ProofOptions: proof.ProofOptions{
			Created: time.Now(),
			Expires: &expires,
			Domain:  &domain,
			Nonce:   &nonce,
		},
	}, &requester, false)
	if err != nil {
		return nil, fmt.Errorf("failed to create verifiable presentation: %w", err)
	}
	token, err := iamClient.AccessToken(ctx, metadata.TokenEndpoint, *vp, submission, scopes)
	if err != nil {
		// the error could be a http error, we just relay it here to make use of any 400 status codes.
		return nil, err
	}
	return &oauth.TokenResponse{
		AccessToken: token.AccessToken,
		ExpiresIn:   token.ExpiresIn,
		TokenType:   token.TokenType,
		Scope:       &scopes,
	}, nil
}

func (s *relyingParty) AuthorizationServerMetadata(ctx context.Context, webdid did.DID) (*oauth.AuthorizationServerMetadata, error) {
	iamClient := iam.NewHTTPClient(s.strictMode, s.httpClientTimeout, s.httpClientTLS)
	metadata, err := iamClient.OAuthAuthorizationServerMetadata(ctx, webdid)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve remote OAuth Authorization Server metadata: %w", err)
	}
	return metadata, nil
}

func chooseVPFormat(formats map[string]map[string][]string) string {
	// They are in preferred order
	if _, ok := formats[vc.JWTPresentationProofFormat]; ok {
		return vc.JWTPresentationProofFormat
	}
	if _, ok := formats["jwt_vp_json"]; ok {
		return vc.JWTPresentationProofFormat
	}
	if _, ok := formats[vc.JSONLDPresentationProofFormat]; ok {
		return vc.JSONLDPresentationProofFormat
	}
	return ""
}

var timeFunc = time.Now

// standalone func for easier testing
func claimsFromRequest(request services.CreateJwtGrantRequest, audience string) map[string]interface{} {
	result := map[string]interface{}{}
	result[jwt.AudienceKey] = audience
	result[jwt.ExpirationKey] = timeFunc().Add(BearerTokenMaxValidity * time.Second).Unix()
	result[jwt.IssuedAtKey] = timeFunc().Unix()
	result[jwt.IssuerKey] = request.Requester
	result[jwt.NotBeforeKey] = 0
	result[jwt.SubjectKey] = request.Authorizer
	result[purposeOfUseClaimDeprecated] = request.Service
	result[purposeOfUseClaim] = request.Service
	if request.IdentityVP != nil {
		result[userIdentityClaim] = *request.IdentityVP
	}
	result[vcClaim] = request.Credentials

	return result
}

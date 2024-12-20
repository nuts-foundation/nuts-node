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
	"fmt"
	"github.com/nuts-foundation/nuts-node/pki"
	"net/url"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/auth/api/auth/v1/client"
	"github.com/nuts-foundation/nuts-node/auth/oauth"
	"github.com/nuts-foundation/nuts-node/auth/services"
	"github.com/nuts-foundation/nuts-node/core"
	nutsCrypto "github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/didman"
	strictHttp "github.com/nuts-foundation/nuts-node/http/client"
	"github.com/nuts-foundation/nuts-node/vcr/credential"
	"github.com/nuts-foundation/nuts-node/vcr/holder"
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
	pkiValidator      pki.Validator
}

// NewRelyingParty returns an implementation of RelyingParty
func NewRelyingParty(
	didResolver resolver.DIDResolver, serviceResolver didman.CompoundServiceResolver, privateKeyStore nutsCrypto.KeyStore,
	wallet holder.Wallet, httpClientTimeout time.Duration, httpClientTLS *tls.Config, strictMode bool, pkiValidator pki.Validator) RelyingParty {
	return &relyingParty{
		keyResolver:       resolver.DIDKeyResolver{Resolver: didResolver},
		serviceResolver:   serviceResolver,
		privateKeyStore:   privateKeyStore,
		httpClientTimeout: httpClientTimeout,
		httpClientTLS:     httpClientTLS,
		strictMode:        strictMode,
		wallet:            wallet,
		pkiValidator:      pkiValidator,
	}
}

// CreateJwtGrant creates a JWT Grant from the given CreateJwtGrantRequest, auth v1 API
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
		validator := credential.FindValidator(verifiableCredential, s.pkiValidator)
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
	signingString, err := s.privateKeyStore.SignJWT(ctx, keyVals, nil, signingKeyID)
	if err != nil {
		return nil, err
	}

	return &services.JwtBearerTokenResult{BearerToken: signingString, AuthorizationServerEndpoint: endpointURL}, nil
}

func (s *relyingParty) RequestRFC003AccessToken(ctx context.Context, jwtGrantToken string, authorizationServerEndpoint url.URL) (*oauth.TokenResponse, error) {
	if s.strictMode && strings.ToLower(authorizationServerEndpoint.Scheme) != "https" {
		return nil, fmt.Errorf("authorization server endpoint must be HTTPS when in strict mode: %s", authorizationServerEndpoint.String())
	}
	httpClient := strictHttp.NewWithTLSConfig(s.httpClientTimeout, s.httpClientTLS)
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
	result[purposeOfUseClaim] = request.Service
	if request.IdentityVP != nil {
		result[userIdentityClaim] = *request.IdentityVP
	}
	result[vcClaim] = request.Credentials

	return result
}

/*
 * Copyright (C) 2024 Nuts community
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
	"bytes"
	"context"
	"crypto"
	"errors"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/auth"
	"github.com/nuts-foundation/nuts-node/auth/client/iam"
	"github.com/nuts-foundation/nuts-node/auth/oauth"
	cryptoNuts "github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/vdr/resolver"
	"net/url"
)

// requestObjectModifier is a function that modifies the Claims/params of an unsigned or signed (JWT) OAuth2 request
type requestObjectModifier func(claims map[string]string)

type jarRequest struct {
	Claims           oauthParameters `json:"claims"`
	Client           string          `json:"client_id"`
	RequestURIMethod string          `json:"request_uri_method"`
}

var _ JAR = &jar{}

type jar struct {
	auth        auth.AuthenticationServices
	jwtSigner   cryptoNuts.JWTSigner
	keyResolver resolver.KeyResolver
	client      iam.Client
}

type JAR interface {
	// Create an unsigned request object.
	// By default, it adds the following parameters:
	//  - client_id
	//  - iss
	//  - aud (if not nil)
	// the request_uri_method is determined by the presence of an audience (get) or not (post)
	Create(client did.DID, clientID string, audience string, modifier requestObjectModifier) jarRequest
	// Sign the jarRequest, which is available on jarRequest.Token.
	// Returns an error if the jarRequest already contains a signed JWT.
	// TODO: check if signature type of client is supported by the AS/wallet.
	Sign(ctx context.Context, claims oauthParameters) (string, error)
	// Parse and validate an incoming authorization request.
	// Requests that do not conform to RFC9101 or OpenID4VP result in an error.
	// The ownMetadata parameter is used when the request contains a request_uri, and it is fetched using HTTP POST;
	// in that case, the metadata is posted to the Authorization Server.
	Parse(ctx context.Context, ownMetadata oauth.AuthorizationServerMetadata, q url.Values) (oauthParameters, error)
}

func NewJAR(auth auth.AuthenticationServices, jwtSigner cryptoNuts.JWTSigner, keyResolver resolver.KeyResolver, client iam.Client) JAR {
	return jar{
		auth:        auth,
		jwtSigner:   jwtSigner,
		keyResolver: keyResolver,
		client:      client,
	}
}

func (j jar) Create(client did.DID, clientID string, audience string, modifier requestObjectModifier) jarRequest {
	return createJarRequest(client, clientID, audience, modifier)
}

func createJarRequest(client did.DID, clientID string, audience string, modifier requestObjectModifier) jarRequest {
	requestURIMethod := "post"
	// default claims for JAR
	params := map[string]string{
		jwt.IssuerKey:       client.String(),
		oauth.ClientIDParam: clientID,
	}
	if audience != "" {
		requestURIMethod = "get"
		params[jwt.AudienceKey] = audience
	}

	// additional claims can be added by the caller
	modifier(params)

	oauthParams := make(oauthParameters, len(params))
	for k, v := range params {
		oauthParams[k] = v
	}
	return jarRequest{
		Claims:           oauthParams,
		Client:           clientID,
		RequestURIMethod: requestURIMethod,
	}
}

func (j jar) Sign(ctx context.Context, claims oauthParameters) (string, error) {
	issuerID := claims.get(jwt.IssuerKey)
	clientDID, err := did.ParseDID(issuerID)
	if err != nil {
		return "", err
	}
	keyId, _, err := j.keyResolver.ResolveKey(*clientDID, nil, resolver.AssertionMethod)
	if err != nil {
		return "", err
	}
	return j.jwtSigner.SignJWT(ctx, claims, nil, keyId)
}

func (j jar) Parse(ctx context.Context, ownMetadata oauth.AuthorizationServerMetadata, q url.Values) (oauthParameters, error) {
	var rawRequestObject string
	var err error
	if rawRequestObject = q.Get(oauth.RequestParam); rawRequestObject != "" {
		if q.Get(oauth.RequestURIParam) != "" {
			return nil, oauth.OAuth2Error{Code: oauth.InvalidRequest, Description: "claims 'request' and 'request_uri' are mutually exclusive"}
		}
	} else if requestURI := q.Get(oauth.RequestURIParam); requestURI != "" {
		switch q.Get(oauth.RequestURIMethodParam) {
		case "", "get": // empty string means client does not support request_uri_method, use 'get'
			rawRequestObject, err = j.auth.IAMClient().RequestObjectByGet(ctx, requestURI)
			if err != nil {
				return nil, oauth.OAuth2Error{Code: oauth.InvalidRequestURI, Description: "failed to get Request Object", InternalError: err}
			}
		case "post":
			rawRequestObject, err = j.auth.IAMClient().RequestObjectByPost(ctx, requestURI, ownMetadata)
			if err != nil {
				return nil, oauth.OAuth2Error{Code: oauth.InvalidRequestURI, Description: "failed to get Request Object", InternalError: err}
			}
		default:
			return nil, oauth.OAuth2Error{Code: oauth.InvalidRequestURIMethod, Description: "unsupported request_uri_method"}
		}
	} else {
		// require_signed_request_object is true, so we reject anything that isn't
		return nil, oauth.OAuth2Error{Code: oauth.InvalidRequest, Description: "authorization request are required to use signed request objects (RFC9101)"}
	}

	// already oauth.OAuth2Errors
	return j.validate(ctx, rawRequestObject, q.Get(oauth.ClientIDParam))
}

// Validate validates a JAR (JWT Authorization Request) and returns the JWT claims.
// the client_id must match the signer of the JWT.
func (j jar) validate(ctx context.Context, rawToken string, clientId string) (oauthParameters, error) {
	var signerKid string
	var publicKey crypto.PublicKey
	// Parse and validate the JWT
	token, err := cryptoNuts.ParseJWT(rawToken, func(kid string) (crypto.PublicKey, error) {
		var err error
		signerKid = kid
		publicKey, err = j.keyResolver.ResolveKeyByID(kid, nil, resolver.AssertionMethod)
		return publicKey, err
	}, jwt.WithValidate(true))
	if err != nil {
		return nil, oauth.OAuth2Error{Code: oauth.InvalidRequestObject, Description: "request signature validation failed", InternalError: err}
	}
	claimsAsMap, err := token.AsMap(ctx)
	if err != nil {
		// very unlikely
		return nil, oauth.OAuth2Error{Code: oauth.InvalidRequestObject, Description: "invalid request parameter", InternalError: err}
	}
	params := parseJWTClaims(claimsAsMap)
	// check client_id claim, it must be the same as the client_id in the request
	if clientId != params.get(oauth.ClientIDParam) {
		return nil, oauth.OAuth2Error{Code: oauth.InvalidRequestObject, Description: "invalid client_id claim in signed authorization request"}
	}
	configuration, err := j.client.OpenIDConfiguration(ctx, clientId)
	if err != nil {
		return nil, oauth.OAuth2Error{Code: oauth.ServerError, Description: "failed to retrieve OpenID configuration", InternalError: err}
	}

	key, exists := configuration.JWKs.LookupKeyID(signerKid)
	if !exists {
		return nil, oauth.OAuth2Error{Code: oauth.InvalidRequestObject, Description: "client_id does not own signer key"}
	}
	if err := compareThumbprint(key, publicKey); err != nil {
		return nil, oauth.OAuth2Error{Code: oauth.InvalidRequestObject, Description: "key mismatch between OpenID configuration and signer key", InternalError: err}
	}
	return params, nil
}

func compareThumbprint(configurationKey jwk.Key, publicKey crypto.PublicKey) error {
	thumbprintLeft, err := configurationKey.Thumbprint(crypto.SHA256)
	if err != nil {
		return err
	}
	signerKey, err := jwk.FromRaw(publicKey)
	if err != nil {
		return err
	}
	thumbprintRight, err := signerKey.Thumbprint(crypto.SHA256)
	if err != nil {
		return err
	}
	if bytes.Compare(thumbprintLeft, thumbprintRight) != 0 {
		return errors.New("key thumbprints do not match")
	}
	return nil
}

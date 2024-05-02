package iam

import (
	"context"
	"crypto"
	"net/url"

	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/auth"
	"github.com/nuts-foundation/nuts-node/auth/oauth"
	cryptoNuts "github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/vdr/resolver"
)

// requestObjectModifier is a function that modifies the Claims/params of an unsigned or signed (JWT) OAuth2 request
type requestObjectModifier func(claims map[string]string)

type jarRequest struct {
	Claims           oauthParameters `json:"claims"`
	Client           did.DID         `json:"client_id"`
	RequestURIMethod string          `json:"request_uri_method"`
}

var _ JAR = &jar{}

type jar struct {
	auth        auth.AuthenticationServices
	jwtSigner   cryptoNuts.JWTSigner
	keyResolver resolver.KeyResolver
}

type JAR interface {
	// Create an unsigned request object.
	// By default, it adds the following parameters:
	// - client_id
	// - jwt.Issuer
	// - jwt.Audience (if server is not nil)
	// - nonce
	Create(client did.DID, server *did.DID, modifier requestObjectModifier) jarRequest
	// Sign the jarRequest, which is available on jarRequest.Token.
	// Returns an error if the jarRequest already contains a signed JWT.
	// TODO: check if signature type of client is supported by the AS/wallet.
	Sign(ctx context.Context, claims oauthParameters) (string, error)
	// Parse and validate an incoming authorization request.
	// Requests that do not conform to RFC9101 or OpenID4VP result in an error.
	Parse(ctx context.Context, ownDID did.DID, q url.Values) (oauthParameters, error)
}

func (j jar) Create(client did.DID, server *did.DID, modifier requestObjectModifier) jarRequest {
	return createJarRequest(client, server, modifier)
}

func createJarRequest(client did.DID, server *did.DID, modifier requestObjectModifier) jarRequest {
	requestURIMethod := "post"
	// default claims for JAR
	params := map[string]string{
		jwt.IssuerKey:       client.String(),
		oauth.ClientIDParam: client.String(),
		// added by default, can be overriden by the caller
		oauth.NonceParam: cryptoNuts.GenerateNonce(),
	}
	if server != nil {
		requestURIMethod = "get"
		params[jwt.AudienceKey] = server.String()
	}

	// additional claims can be added by the caller
	modifier(params)

	oauthParams := make(oauthParameters, len(params))
	for k, v := range params {
		oauthParams[k] = v
	}
	return jarRequest{
		Claims:           oauthParams,
		Client:           client,
		RequestURIMethod: requestURIMethod,
	}
}

func (j jar) Sign(ctx context.Context, claims oauthParameters) (string, error) {
	clientID := claims.get(oauth.ClientIDParam)
	clientDID, err := did.ParseDID(clientID)
	if err != nil {
		return "", err
	}
	keyId, _, err := j.keyResolver.ResolveKey(*clientDID, nil, resolver.AssertionMethod)
	if err != nil {
		return "", err
	}
	return j.jwtSigner.SignJWT(ctx, claims, nil, keyId.String())
}

func (j jar) Parse(ctx context.Context, ownDID did.DID, q url.Values) (oauthParameters, error) {
	var rawRequestObject string
	var err error
	if rawRequestObject = q.Get(oauth.RequestParam); rawRequestObject != "" {
		if q.Has(oauth.RequestURIParam) {
			return nil, oauth.OAuth2Error{Code: oauth.InvalidRequest, Description: "Claims 'request' and 'request_uri' are mutually exclusive"}
		}
	} else if requestURI := q.Get(oauth.RequestURIParam); requestURI != "" {
		if q.Get(oauth.RequestURIMethodParam) == "post" { // case-sensitive match
			baseURL, err := createOAuth2BaseURL(ownDID)
			if err != nil {
				// can't fail
				return nil, err
			}
			walletMetadata := authorizationServerMetadata(ownDID.URI().URL, *baseURL)
			// TODO: create wallet_metadata and post to requestURI.
			_ = walletMetadata
			// TODO: do we need wallet_nonce? only way to reach nuts_node is server2server comms.
		}
		rawRequestObject, err = j.auth.IAMClient().RequestObject(ctx, requestURI)
		if err != nil {
			return nil, oauth.OAuth2Error{Code: oauth.InvalidRequestURI, Description: "failed to get Request Object", InternalError: err}
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
	// Parse and validate the JWT
	token, err := cryptoNuts.ParseJWT(rawToken, func(kid string) (crypto.PublicKey, error) {
		signerKid = kid
		return j.keyResolver.ResolveKeyByID(kid, nil, resolver.AssertionMethod)
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
	// check if the signer of the JWT is the client
	signer, err := did.ParseDIDURL(signerKid)
	if err != nil {
		// very unlikely since the key has already been resolved
		return nil, oauth.OAuth2Error{Code: oauth.InvalidRequestObject, Description: "invalid signer", InternalError: err}
	}
	if signer.DID.String() != clientId {
		return nil, oauth.OAuth2Error{Code: oauth.InvalidRequestObject, Description: "client_id does not match signer of authorization request"}
	}
	return params, nil
}

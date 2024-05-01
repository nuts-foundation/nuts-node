package iam

import (
	"context"
	"crypto"
	"errors"
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

type requestObject struct {
	Claims oauthParameters `json:"claims"`
	Token  string          `json:"token,omitempty"`
}

func (ro requestObject) client() did.DID {
	// set by JAR.Create, so always present
	return did.MustParseDID(ro.Claims.get(oauth.ClientIDParam))
}

func (ro requestObject) nonce() string {
	// set by JAR.Create, so always present
	return ro.Claims.get(oauth.NonceParam)
}

func (ro requestObject) signed() bool {
	return ro.Token != ""
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
	Create(client did.DID, server *did.DID, modifier requestObjectModifier) *requestObject
	// Sign the requestObject, which is available on requestObject.Token.
	// Returns an error if the requestObject already contains a signed JWT.
	// TODO: check if signature type of client is supported by the AS/wallet.
	Sign(ctx context.Context, ro *requestObject) error
	// Parse and validate an incoming authorization request.
	// Requests that do not conform to RFC9101 or OpenID4VP result in an error.
	Parse(ctx context.Context, ownDID did.DID, q url.Values) (*requestObject, error)
}

func (j jar) Create(client did.DID, server *did.DID, modifier requestObjectModifier) *requestObject {
	// default claims for JAR
	params := map[string]string{
		jwt.IssuerKey:       client.String(),
		oauth.ClientIDParam: client.String(),
		// added by default, can be overriden by the caller
		oauth.NonceParam: cryptoNuts.GenerateNonce(),
	}
	if server != nil {
		params[jwt.AudienceKey] = server.String()
	}

	// additional claims can be added by the caller
	modifier(params)

	oauthParams := make(oauthParameters, len(params))
	for k, v := range params {
		oauthParams[k] = v
	}
	return &requestObject{
		Claims: oauthParams,
	}
}

func (j jar) Sign(ctx context.Context, ro *requestObject) error {
	if ro.signed() {
		return errors.New("already signed")
	}
	keyId, _, err := j.keyResolver.ResolveKey(ro.client(), nil, resolver.AssertionMethod)
	if err != nil {
		return err
	}
	ro.Token, err = j.jwtSigner.SignJWT(ctx, ro.Claims, nil, keyId.String())
	return err
}

func (j jar) Parse(ctx context.Context, ownDID did.DID, q url.Values) (*requestObject, error) {
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

	params, err := j.validate(ctx, rawRequestObject, q.Get(oauth.ClientIDParam))
	if err != nil {
		// already oauth.OAuth2Errors
		return nil, err
	}

	return &requestObject{
		Claims: params,
		Token:  rawRequestObject,
	}, nil
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

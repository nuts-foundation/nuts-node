package iam

import (
	"context"
	crypt "crypto"
	"encoding/json"
	"errors"
	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/auth/log"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/crypto"
	http2 "github.com/nuts-foundation/nuts-node/http"
	"github.com/nuts-foundation/nuts-node/storage"
	"github.com/nuts-foundation/nuts-node/vcr/holder"
	"github.com/nuts-foundation/nuts-node/vcr/pe"
	"github.com/nuts-foundation/nuts-node/vcr/verifier"
	"github.com/nuts-foundation/nuts-node/vdr/didweb"
	"github.com/nuts-foundation/nuts-node/vdr/resolver"
	"io"
	"maps"
	"net/http"
	"net/url"
	"slices"
	"time"
)

const oid4vicSessionValidity = 15 * time.Minute

type Oid4vciSession struct {
	HolderDid   string
	IssuerDid   string
	RedirectUrl string
	RedirectUri string
}

func (r Wrapper) StartOid4vciIssuance(ctx context.Context, request StartOid4vciIssuanceRequestObject) (StartOid4vciIssuanceResponseObject, error) {
	if request.Body == nil {
		// why did oapi-codegen generate a pointer for the body??
		return nil, core.InvalidInputError("missing request body")
	}
	requestHolder, err := did.ParseDID(request.Did)
	if err != nil {
		return nil, core.NotFoundError("did not found: %w", err)
	}
	isWallet, err := r.vdr.IsOwner(ctx, *requestHolder)
	if err != nil {
		return nil, err
	}
	if !isWallet {
		return nil, core.InvalidInputError("did not owned by this node: %w", err)
	}

	issuerDid, err := did.ParseDID(request.Body.Issuer)
	if err != nil {
		return nil, core.NotFoundError("did not found: %w", err)
	}

	metadata, err := r.auth.MitzXNutsIAMClient().OpenIdCredentialIssuerMetadata(ctx, *issuerDid)
	if err != nil {
		return nil, err
	}
	if len(metadata.AuthorizationServers) == 0 {
		return nil, core.NotFoundError("cannot locate any authorization endpoint in %s", issuerDid.String())
	}
	for i := range metadata.AuthorizationServers {
		// TODO: do some kind of logic here on supported credentials
		serverURL, err := url.Parse(metadata.AuthorizationServers[i])
		if err != nil {
			return nil, err
		}
		metadataFromUrl, err := r.auth.MitzXNutsIAMClient().OpenIdConfiguration(ctx, *serverURL)
		if err != nil {
			return nil, err
		}
		endpoint, err := url.Parse(metadataFromUrl.AuthorizationEndpoint)
		if err != nil {
			return nil, err
		}

		authorizationDetails := []byte("[]")
		if len(request.Body.AuthorizationDetails) > 0 {
			authorizationDetails, _ = json.Marshal(request.Body.AuthorizationDetails)
			if err != nil {
				return nil, err
			}
		}

		sessionID := uuid.NewString()

		params := generatePKCEParams()
		err = r.getSessionStore("pkce").Put(sessionID, *params)
		if err != nil {
			return nil, err
		}

		requesterDidUrl, err := didweb.DIDToURL(*requestHolder)
		if err != nil {
			return nil, err
		}
		redirectUri, err := url.Parse("https://" + requesterDidUrl.Host + "/iam/oid4vci/" + sessionID + "/callback")
		if err != nil {
			return nil, err
		}
		err = r.getSessionStore("oid4vci").Put(sessionID, &Oid4vciSession{
			HolderDid:   requestHolder.String(),
			IssuerDid:   issuerDid.String(),
			RedirectUrl: request.Body.RedirectURL,
			RedirectUri: redirectUri.String(),
		})
		if err != nil {
			return nil, err
		}

		httpRequest := ctx.Value(httpRequestContextKey).(*http.Request)
		host := httpRequest.Host
		claims := map[string]interface{}{
			"session": sessionID,
		}
		proofJwt, err := r.proofJwt(ctx, *requestHolder, *issuerDid, &claims)
		if err != nil {
			return nil, err
		}

		redirectUrl := http2.AddQueryParams(*endpoint, map[string]string{
			"user_hint":             proofJwt,
			"wallet_issuer":         "https://" + host + "/iam/oid4vci/dcr/" + sessionID,
			"response_type":         "code",
			"client_id":             requestHolder.String(),
			"authorization_details": string(authorizationDetails),
			"redirect_uri":          redirectUri.String(),
			"code_challenge":        params.Challenge,
			"code_challenge_method": params.ChallengeMethod,
		})
		return StartOid4vciIssuance302Response{
			Headers: StartOid4vciIssuance302ResponseHeaders{Location: redirectUrl.String()},
		}, nil

	}
	return nil, core.NotFoundError("cannot locate an authorization endpoint in %s", metadata.AuthorizationServers)
}

func (r Wrapper) DcrOid4vpMetadata(ctx context.Context, request DcrOid4vpMetadataRequestObject) (DcrOid4vpMetadataResponseObject, error) {
	httpRequest := ctx.Value(httpRequestContextKey).(*http.Request)
	host := httpRequest.Host
	sessionId := request.SessionId
	oid4vciSession := Oid4vciSession{}
	err := r.getSessionStore("oid4vci").Get(sessionId, &oid4vciSession)
	if err != nil {
		return nil, err
	}
	holderDid, err := did.ParseDID(oid4vciSession.HolderDid)
	if err != nil {
		return nil, err
	}
	response := DcrOid4vpMetadata200JSONResponse{
		AuthorizationEndpoint:                  "https://" + host + "/iam/oid4vci/dcr/" + sessionId + "/authorize",
		IdTokenSigningAlgValuesSupported:       crypto.GetSupportedAlgorithms(),
		IdTokenTypesSupported:                  &[]string{"vp_token"},
		Issuer:                                 holderDid.String(),
		RequestObjectSigningAlgValuesSupported: crypto.GetSupportedAlgorithms(),
		ResponseTypesSupported:                 nil,
		ScopesSupported:                        nil,
		SubjectSyntaxTypesSupported:            nil,
		SubjectTypesSupported:                  nil,
	}
	rv := response
	return rv, nil
}

func (r Wrapper) DcrOid4vpAuthorize(ctx context.Context, request DcrOid4vpAuthorizeRequestObject) (DcrOid4vpAuthorizeResponseObject, error) {
	requestJwt := request.Params.Request
	requestToken, err := crypto.ParseJWT(requestJwt, func(kid string) (crypt.PublicKey, error) {
		keyResolver := resolver.DIDKeyResolver{Resolver: r.vdr.Resolver()}
		return keyResolver.ResolveKeyByID(kid, nil, resolver.NutsSigningKeyType)
	}, jwt.WithAcceptableSkew(5*time.Second))
	if err != nil {
		return nil, err
	}

	definition, err := r.getPresentationDefinition(requestToken)
	if err != nil {
		return nil, err
	}

	sessionId := request.SessionId
	oid4vciSession := Oid4vciSession{}
	err = r.getSessionStore("oid4vci").Get(sessionId, &oid4vciSession)
	if err != nil {
		return nil, err
	}

	holderDid, err := did.ParseDID(oid4vciSession.HolderDid)
	if err != nil {
		return nil, err
	}
	redirectUri, err := getRequiredTokenValue(requestToken, "redirect_uri")
	if err != nil {
		return nil, err
	}
	state, err := getRequiredTokenValue(requestToken, "state")
	if err != nil {
		return nil, err
	}
	redirectURL, err := url.Parse(*redirectUri)
	if err != nil {
		return nil, err
	}
	selected, err := r.findCredentialWithDescriptors(ctx, holderDid, definition.InputDescriptors)
	if err != nil {
		return nil, err
	}
	presentation, err := r.vcr.Wallet().BuildPresentation(ctx, []vc.VerifiableCredential{*selected}, holder.PresentationOptions{
		Format: "ldp_vp",
	}, holderDid, false)
	values := redirectURL.Query()
	values.Set("vp_token", presentation.Raw())
	values.Set("state", *state)
	redirectURL.RawQuery = values.Encode()

	return &DcrOid4vpAuthorize302Response{
		Headers: DcrOid4vpAuthorize302ResponseHeaders{
			Location: redirectURL.String(),
		},
	}, nil

}

func (r Wrapper) findCredentialWithDescriptors(ctx context.Context, holderDid *did.DID, inputDescriptors []*pe.InputDescriptor) (*VerifiableCredential, error) {
	credentials, err := r.vcr.Wallet().List(ctx, *holderDid)
	if err != nil {
		return nil, err
	}
	for i := range credentials {
		credential := credentials[i]
		for j := range inputDescriptors {
			descriptor := inputDescriptors[j]
			if descriptor != nil {
				types := credential.Type
				for k := range types {
					typeUri := types[k]
					if descriptor.Name == typeUri.String() {
						return &credential, nil
					}
				}
			}
		}
	}
	return nil, core.Error(400, "Cannot locate any matching credential")
}
func getRequiredTokenValue(requestToken jwt.Token, key string) (*string, error) {
	rv, ok := requestToken.Get(key)
	if !ok {
		return nil, core.Error(400, "Missing required request param in request object: "+key)
	}
	value := rv.(string)
	return &value, nil
}

func (r Wrapper) getPresentationDefinition(requestToken jwt.Token) (*PresentationDefinition, error) {
	definition := PresentationDefinition{}
	presentationDefinition, has := requestToken.Get("presentation_definition")
	if has {
		bytes, err := json.Marshal(presentationDefinition)
		if err != nil {
			return nil, err
		}
		err = json.Unmarshal(bytes, &definition)
		if err != nil {
			return nil, err
		}
	} else {
		presentationDefinitionUri, has := requestToken.Get("presentation_definition_uri")
		if has {
			presentationDefinitionURI := presentationDefinitionUri.(string)
			resp, err := http.Get(presentationDefinitionURI)
			if err != nil {
				return nil, err
			}
			defer func(Body io.ReadCloser) {
				err := Body.Close()
				if err != nil {
					log.Logger().WithError(err).Warn("Trouble closing reader")
				}
			}(resp.Body)

			body, err := io.ReadAll(resp.Body)
			if err != nil {
				return nil, err
			}

			err = json.Unmarshal(body, &definition)
			if err != nil {
				return nil, err
			}
		} else {
			return nil, errors.New("presentation_definition or presentation_definition_uri is missing")
		}

	}
	return &definition, nil
}

func (r Wrapper) CallbackOid4vciIssuance(ctx context.Context, request CallbackOid4vciIssuanceRequestObject) (CallbackOid4vciIssuanceResponseObject, error) {

	sessionId := request.SessionId
	code := request.Params.Code

	oid4vciSession := Oid4vciSession{}
	err := r.getSessionStore("oid4vci").Get(sessionId, &oid4vciSession)
	if err != nil {
		return nil, err
	}

	pkceParams := PKCEParams{}
	err = r.getSessionStore("pkce").Get(sessionId, &pkceParams)
	if err != nil {
		return nil, err
	}

	issuerDid, err := did.ParseDID(oid4vciSession.IssuerDid)
	holderDid, err := did.ParseDID(oid4vciSession.HolderDid)
	metadata, err := r.auth.MitzXNutsIAMClient().OpenIdCredentialIssuerMetadata(ctx, *issuerDid)
	if len(metadata.AuthorizationServers) == 0 {
		return nil, core.NotFoundError("cannot locate any authorization endpoint in %s", issuerDid.String())
	}
	for i := range metadata.AuthorizationServers {
		serverURL, err := url.Parse(metadata.AuthorizationServers[i])
		if err != nil {
			return nil, err
		}
		metadataFromUrl, err := r.auth.MitzXNutsIAMClient().OpenIdConfiguration(ctx, *serverURL)
		if err != nil {
			return nil, err
		}

		tokenEndpoint := metadataFromUrl.TokenEndpoint
		response, err := r.auth.MitzXNutsIAMClient().AccessTokenOid4vci(ctx, holderDid.String(), tokenEndpoint, oid4vciSession.RedirectUri, code, &pkceParams.Verifier)
		println(response.AccessToken)

		proofJwt, err := r.proofJwt(ctx, *holderDid, *issuerDid, nil)
		if err != nil {
			return nil, err
		}

		credentials, err := r.auth.MitzXNutsIAMClient().VerifiableCredentials(ctx, metadata.CredentialEndpoint, response.AccessToken, proofJwt)
		if err != nil {
			return nil, err
		}
		credential, err := vc.ParseVerifiableCredential(credentials.Credential)
		if err != nil {
			return nil, err
		}
		for t := range credential.Type {
			trusted, err := r.vcr.Trusted(credential.Type[t])
			if err != nil {
				return nil, err
			}
			if !slices.Contains(trusted, credential.Issuer) {
				err := r.vcr.Trust(credential.Type[t], credential.Issuer)
				if err != nil {
					return nil, err
				}
			}

		}

		err = r.vcr.Verifier().Verify(*credential, true, true, nil)
		if err != nil {
			return nil, err
		}
		err = r.vcr.Wallet().Put(ctx, *credential)
		if err != nil {
			return nil, err
		}
	}

	return CallbackOid4vciIssuance302Response{
		Headers: CallbackOid4vciIssuance302ResponseHeaders{Location: oid4vciSession.RedirectUrl},
	}, nil
}

func (r Wrapper) proofJwt(ctx context.Context, issuerDid did.DID, audienceDid did.DID, additionalClaims *map[string]interface{}) (string, error) {
	keyResolver := resolver.DIDKeyResolver{Resolver: r.vdr.Resolver()}
	kid, _, err := keyResolver.ResolveKey(issuerDid, nil, resolver.NutsSigningKeyType)
	if err != nil {
		return "", err
	}
	key, err := r.keyStore.Resolve(ctx, kid.String())
	if err != nil {
		return "", err
	}
	jti, err := uuid.NewUUID()
	if err != nil {
		return "", err
	}
	claims := map[string]interface{}{
		"iss": issuerDid.String(),
		"aud": audienceDid.String(),
		"jti": jti.String(),
	}
	if additionalClaims != nil {
		maps.Copy(claims, *additionalClaims)
	}
	headers := map[string]interface{}{}
	proofJwt, err := r.keyStore.SignJWT(ctx, claims, headers, key)
	if err != nil {
		return "", err
	}
	return proofJwt, nil
}

func (r Wrapper) SearchWallet(ctx context.Context, request SearchWalletRequestObject) (SearchWalletResponseObject, error) {
	holderDid, err := did.ParseDID(request.Did)
	if err != nil {
		return nil, err
	}
	list, err := r.vcr.Wallet().List(ctx, *holderDid)
	if err != nil {
		return nil, err
	}
	results := make([]SearchVCResult, len(list))
	for i := range list {
		resolvedVC := list[i]
		var revocation *Revocation
		revocation, err := r.vcr.Verifier().GetRevocation(*resolvedVC.ID)
		if err != nil && !errors.Is(err, verifier.ErrNotFound) {
			return nil, err
		}
		results[i] = SearchVCResult{VerifiableCredential: resolvedVC, Revocation: revocation}
	}
	response := SearchWallet200JSONResponse{
		results,
	}
	return response, nil
}

func (r Wrapper) DeleteWalletCredential(ctx context.Context, request DeleteWalletCredentialRequestObject) (DeleteWalletCredentialResponseObject, error) {
	holderDid, err := did.ParseDID(request.Did)
	if err != nil {
		return nil, err
	}
	list, err := r.vcr.Wallet().List(ctx, *holderDid)
	if err != nil {
		return nil, err
	}
	for i := range list {
		resolvedVC := list[i]
		if resolvedVC.ID.String() == request.Id {
			err = r.vcr.Wallet().Delete(ctx, *holderDid, *resolvedVC.ID)
			if err != nil {
				return nil, err
			}
			continue
		}
	}
	return nil, nil
}

func (r Wrapper) getSessionStore(keys ...string) storage.SessionStore {
	return r.storageEngine.GetSessionDatabase().GetStore(oid4vicSessionValidity, keys...)
}

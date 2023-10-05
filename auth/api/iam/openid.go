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

package iam

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/lestrrat-go/jwx/jwt"
	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/vcr/credential"
	"github.com/nuts-foundation/nuts-node/vcr/holder"
	"github.com/nuts-foundation/nuts-node/vcr/pe"
	"github.com/nuts-foundation/nuts-node/vdr/resolver"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"
)

const sessionExpiry = 5 * time.Minute

// createOpenIDAuthzRequest creates a new Authorization Request as specified by OpenID4VP: https://openid.net/specs/openid-4-verifiable-presentations-1_0.html.
// It is sent by a verifier to a wallet, to request one or more verifiable credentials as verifiable presentation from the wallet.
func (r Wrapper) createOpenIDAuthzRequest(ctx context.Context, scope string, state string, presentationDefinition pe.PresentationDefinition, responseTypes []string, redirectURL url.URL, verifierDID did.DID) (string, error) {
	params := make(map[string]interface{})
	params[scopeParam] = scope
	params[redirectURIParam] = redirectURL.String()
	// TODO: Specifying client_metadata_uri causes Sphereon Wallet to conclude the RP (Nuts Node) does not support SIOPv2 ID1
	// (since client_metadata_uri was specified later, in d11?).
	// Leading to the error message: RP does not support spec version 70, supported versions: 71
	// Which is actually pretty weird, since the URI scheme used is openid-vc: (from JWT VC presentation profile),
	// instead of openid: (from SIOPv2 ID1).
	//params[clientMetadataURIParam] = r.auth.PublicURL().JoinPath(".well-known", "oauth-authorization-server", identifierPath).String()
	params[responseTypeParam] = strings.Join(responseTypes, " ")
	// TODO: What about including other (than openid) scopes?
	params[clientIDParam] = verifierDID.String()
	params["iss"] = verifierDID.String()
	params["sub"] = verifierDID.String()
	params["nbf"] = time.Now()
	params["jti"] = uuid.NewString()
	params["iat"] = time.Now()
	params["exp"] = time.Now().Add(time.Minute)
	params["nonce"] = generateCode()
	params["state"] = state
	// TODO: This should be the RPs metadata
	params["registration"] = map[string]interface{}{
		"client_name":                                 "Nuts Node",
		"client_purpose":                              "Please share this information to perform medical data exchanges.",
		"id_token_signing_alg_values_supported":       []string{"EdDSA", "ES256", "ES256K"},
		"request_object_signing_alg_values_supported": []string{"EdDSA", "ES256", "ES256K"},
		//"response_types_supported":                    []string{"id_token", "vp_token"},
		"response_types_supported":       []string{"id_token"}, // TODO
		"scopes_supported":               []string{scope},
		"subject_types_supported":        []string{"pairwise"},                                             // what is this?
		"subject_syntax_types_supported": []string{"did:jwk", "did:web", "did:ion", "did:key", "did:ethr"}, // TODO: did:ion, did:ethr is not actually supported
		"vp_formats": map[string]interface{}{
			// TODO: JWT VC presentation profile implementation, does not specify JSON-LD
			"jwt_vc": map[string]interface{}{
				"alg": []string{"EdDSA", "ES256", "ES256K"},
			},
			"jwt_vp": map[string]interface{}{
				"alg": []string{"EdDSA", "ES256", "ES256K"},
			},
		},
	}

	for _, responseType := range responseTypes {
		switch responseType {
		case responseTypeIDToken:
			// JWT-VC Presentation profile (SIOPv2)
			params[responseModeParam] = responseModePost
			params["claims"] = map[string]interface{}{
				"vp_token": map[string]interface{}{
					"presentation_definition": presentationDefinition,
				},
			}
		case responseTypeVPToken:
			// OpenID4VP
			params[responseModeParam] = responseModeDirectPost
		}
	}

	requestObjectJSON, _ := json.MarshalIndent(params, " ", "  ")
	println(string(requestObjectJSON))

	// Create request JWT
	// Sign Request Object with assertionMethod key of verifier DID
	keyResolver := resolver.PrivateKeyResolver{
		DIDResolver:     r.vdr.Resolver(),
		PrivKeyResolver: r.keyStore,
	}
	signingKey, err := keyResolver.ResolvePrivateKey(ctx, verifierDID, nil, resolver.NutsSigningKeyType)
	if err != nil {
		return "", fmt.Errorf("failed to resolve signing key (did=%s): %w", verifierDID, err)
	}
	return r.keyStore.SignJWT(ctx, params, nil, signingKey)
}

// sendPresentationRequest creates a new OpenID4VP Presentation Requests and "sends" it to the wallet, by redirecting the user-agent to the wallet's authorization endpoint.
// It is sent by a verifier to a wallet, to request one or more verifiable credentials as verifiable presentation from the wallet.
func (r Wrapper) sendPresentationRequest(ctx context.Context, response http.ResponseWriter, scope []string,
	redirectURL url.URL, verifierIdentifier url.URL, walletIdentifier url.URL) error {
	// TODO: Lookup wallet metadata for correct authorization endpoint. But for Nuts nodes, we derive it from the walletIdentifier
	authzEndpoint := walletIdentifier.JoinPath("/authorize")
	params := make(map[string]string)
	params[scopeParam] = strings.Join(scope, " ")
	params[redirectURIParam] = redirectURL.String()
	// TODO: Check this
	params[clientMetadataURIParam] = verifierIdentifier.JoinPath("/.well-known/openid-wallet-metadata/metadata.xml").String()
	params[responseModeParam] = responseModeDirectPost
	params[responseTypeParam] = strings.Join([]string{responseTypeVPToken, responseTypeIDToken}, " ")
	// TODO: Depending on parameter size, we either use redirect with query parameters or a form post.
	//       For simplicity, we now just query parameters.
	result := AddQueryParams(*authzEndpoint, params)
	response.Header().Add("Location", result.String())
	response.WriteHeader(http.StatusFound)
	return nil
}

// handlePresentationRequest handles an Authorization Request as specified by OpenID4VP: https://openid.net/specs/openid-4-verifiable-presentations-1_0.html.
// It is handled by a wallet, called by a verifier who wants the wallet to present one or more verifiable credentials.
func (r Wrapper) handlePresentationRequest(params map[string]string, session *Session) (HandleAuthorizeRequestResponseObject, error) {
	ctx := context.TODO()
	// Presentation definition is always derived from the scope.
	// Later on, we might support presentation_definition and/or presentation_definition_uri parameters instead of scope as well.
	if err := assertParamNotPresent(params, presentationDefParam, presentationDefUriParam); err != nil {
		return nil, err
	}
	if err := assertParamPresent(params, scopeParam); err != nil {
		return nil, err
	}
	if err := assertParamPresent(params, responseTypeParam); err != nil {
		return nil, err
	}
	// Not supported: client_id_schema, client_metadata
	if err := assertParamNotPresent(params, clientIDSchemeParam, clientMetadataParam); err != nil {
		return nil, err
	}
	// Required: client_metadata_uri
	if err := assertParamPresent(params, clientMetadataURIParam); err != nil {
		return nil, err
	}
	// Response mode is always direct_post for now
	if params[responseModeParam] != responseModeDirectPost {
		return nil, OAuth2Error{
			Code:        InvalidRequest,
			Description: "response_mode must be direct_post",
			RedirectURI: session.RedirectURI,
		}
	}

	// TODO: This is the easiest for now, but is this the way?
	// For compatibility, we probably need to support presentation_definition and/or presentation_definition_uri.
	presentationDefinition := r.auth.PresentationDefinitions().ByScope(params[scopeParam])
	if presentationDefinition == nil {
		return nil, OAuth2Error{
			Code:        InvalidRequest,
			Description: fmt.Sprintf("unsupported scope for presentation exchange: %s", params[scopeParam]),
			RedirectURI: session.RedirectURI,
		}
	}

	// Render HTML
	templateParams := struct {
		SessionID            string
		RequiresUserIdentity bool
		VerifierName         string
		Credentials          []CredentialInfo
	}{
		// TODO: Maybe this should the verifier name be read from registered client metadata?
		VerifierName:         ssi.MustParseURI(session.RedirectURI).Host,
		RequiresUserIdentity: slices.Contains(session.ResponseType, "id_token"),
	}

	// TODO: https://github.com/nuts-foundation/nuts-node/issues/2357
	// TODO: Retrieve presentation definition
	credentials, err := r.vcr.Wallet().List(ctx, session.OwnDID)
	if err != nil {
		return nil, err
	}
	var ownCredentials []vc.VerifiableCredential
	for _, cred := range credentials {
		var subject []credential.NutsOrganizationCredentialSubject
		if err = cred.UnmarshalCredentialSubject(&subject); err != nil {
			return nil, fmt.Errorf("unable to unmarshal credential: %w", err)
		}
		if len(subject) != 1 {
			continue
		}
		isOwner, _ := r.vdr.IsOwner(ctx, did.MustParseDID(subject[0].ID))
		if isOwner {
			ownCredentials = append(ownCredentials, cred)
		}
	}

	// TODO: https://github.com/nuts-foundation/nuts-node/issues/2359
	// TODO: What if multiple credentials of the same type match?
	_, matchingCredentials, err := presentationDefinition.Match(credentials)
	if err != nil {
		return nil, fmt.Errorf("unable to match presentation definition: %w", err)
	}
	var credentialIDs []string
	for _, matchingCredential := range matchingCredentials {
		templateParams.Credentials = append(templateParams.Credentials, makeCredentialInfo(matchingCredential))
		credentialIDs = append(credentialIDs, matchingCredential.ID.String())
	}
	session.ServerState["openid4vp_credentials"] = credentialIDs

	sessionID := uuid.NewString()
	err = r.storageEngine.GetSessionDatabase().GetStore(sessionExpiry, session.OwnDID.String(), "session").Put(sessionID, *session)
	if err != nil {
		return nil, err
	}
	templateParams.SessionID = sessionID

	// TODO: Support multiple languages
	buf := new(bytes.Buffer)
	err = r.templates.ExecuteTemplate(buf, "authz_wallet_en.html", templateParams)
	if err != nil {
		return nil, fmt.Errorf("unable to render authz page: %w", err)
	}
	return HandleAuthorizeRequest200TexthtmlResponse{
		Body:          buf,
		ContentLength: int64(buf.Len()),
	}, nil
}

// handleAuthConsent handles the authorization consent form submission.
func (r Wrapper) handlePresentationRequestAccept(c echo.Context) error {
	ownDID := idToDID(c.Param("id"))
	// TODO: Needs authentication?
	session, err := r.getSessionByID(ownDID, c.FormValue("sessionID"))
	if err != nil {
		return err
	}

	// TODO: Change to loading from wallet
	credentialIDs, ok := session.ServerState["openid4vp_credentials"].([]string)
	if !ok {
		return errors.New("invalid session (missing credentials in session)")
	}
	var credentials []vc.VerifiableCredential
	for _, id := range credentialIDs {
		credentialID, _ := ssi.ParseURI(id)
		if credentialID == nil {
			continue // should be impossible
		}
		cred, err := r.vcr.Resolve(*credentialID, nil)
		if err != nil {
			return err
		}
		credentials = append(credentials, *cred)
	}
	presentationDefinition := r.auth.PresentationDefinitions().ByScope(session.Scope[0]) // what about the others? Is this right?
	if presentationDefinition == nil {
		return fmt.Errorf("unsupported scope for presentation exchange: %s", session.Scope)
	}
	// TODO: Options
	resultParams := map[string]string{}
	presentationSubmission, credentials, err := presentationDefinition.Match(credentials)
	if err != nil {
		// Matched earlier, shouldn't happen
		return err
	}
	presentationSubmissionJSON, _ := json.Marshal(presentationSubmission)
	resultParams[presentationSubmissionParam] = string(presentationSubmissionJSON)
	verifiablePresentation, err := r.vcr.Wallet().BuildPresentation(c.Request().Context(), credentials, holder.PresentationOptions{}, &session.OwnDID, false)
	if err != nil {
		return err
	}
	verifiablePresentationJSON, _ := verifiablePresentation.MarshalJSON()
	resultParams[vpTokenParam] = string(verifiablePresentationJSON)

	// TODO: check response mode, and submit accordingly (direct_post)
	return c.Redirect(http.StatusFound, session.CreateRedirectURI(resultParams))
}

func (r Wrapper) handleOpenIDAuthzResponse(session *Session, params url.Values) error {
	for _, responseType := range session.ResponseType {
		switch responseType {
		case responseTypeIDToken:
			// SIOPv2
			return r.handleSIOPv2AuthzResponse(session, params)
		case responseType:
			// OpenID4VP
			return r.handleOpenID4VPAuthzResponse(session, params)
		default:
			return errors.New("TODO: implement handling of " + responseType)
		}
	}
	return errors.New("invalid session: no response types") // can't happen
}

func (r Wrapper) handleSIOPv2AuthzResponse(session *Session, params url.Values) error {
	if !params.Has(vpTokenParam) {
		return missingParameterError(vpTokenParam, session)
	}
	vpToken, err := jwt.Parse([]byte(params.Get(vpTokenParam)))
	if err != nil {
		return invalidParameterError(vpTokenParam, session, err)
	}
	// TODO: Verify signature
	if verifiablePresentationMap, ok := vpToken.Get("vp"); !ok {
		return OAuth2Error{
			Code:        InvalidRequest, // TODO: right?
			Description: fmt.Sprintf("missing %s claim in %s", vpClaim, vpTokenParam),
		}
	} else {
		vpJSON, _ := json.Marshal(verifiablePresentationMap)
		vp, err := vc.ParseVerifiablePresentation(string(vpJSON))
		if err != nil {
			return OAuth2Error{
				Code:          InvalidRequest, // TODO: right?
				Description:   fmt.Sprintf("invalid %s claim in %s", vpClaim, vpTokenParam),
				InternalError: err,
			}
		}
		session.IDToken = vp
	}
	return nil
}

func (r Wrapper) handleOpenID4VPAuthzResponse(session *Session, params url.Values) error {
	if !params.Has(vpTokenParam) {
		return missingParameterError(vpTokenParam, session)
	}
	vp, err := vc.ParseVerifiablePresentation(params.Get(vpTokenParam))
	if err != nil {
		return invalidParameterError(vpTokenParam, session, err)
	}
	// TODO: verify signature, VCs, VPs, etc
	session.VPToken = vp
	return nil
}

func (r Wrapper) handleGetOpenIDRequestObject(echoCtx echo.Context) error {
	ownID := idToDID(echoCtx.Param("id"))
	session, err := r.getSessionByID(ownID, echoCtx.Param("sessionID"))
	if err != nil {
		return err
	}
	return echoCtx.String(http.StatusOK, session.RequestObject)
}

func (r Wrapper) handleGetOpenIDSession(echoCtx echo.Context) error {
	ownID := idToDID(echoCtx.Param("id"))
	session, err := r.getSessionByID(ownID, echoCtx.Param("sessionID"))
	if err != nil {
		return err
	}
	return echoCtx.JSON(http.StatusOK, session)
}

func assertParamPresent(params map[string]string, param ...string) error {
	for _, curr := range param {
		if len(params[curr]) == 0 {
			return fmt.Errorf("%s parameter must be present", curr)
		}
	}
	return nil
}

func assertParamNotPresent(params map[string]string, param ...string) error {
	for _, curr := range param {
		if len(params[curr]) > 0 {
			return fmt.Errorf("%s parameter must not be present", curr)
		}
	}
	return nil
}

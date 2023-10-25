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

// This file contains functions for the OpenID Relying Party (RP) role.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/lestrrat-go/jwx/jwt"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/vcr/pe"
	"github.com/nuts-foundation/nuts-node/vdr/resolver"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const sessionExpiry = 5 * time.Minute

// createOpenIDAuthzRequest creates a new SIOPv2/OpenID4VP Authorization Request.
// It returns the request object as JWT-Secured Authorization Request (https://www.rfc-editor.org/rfc/rfc9101.html).
// It is sent by a verifier to a wallet, to request one or more verifiable credentials as verifiable presentation from the wallet.
func (r Wrapper) createOpenIDAuthzRequest(ctx context.Context, scope string, state string, presentationDefinition pe.PresentationDefinition, responseTypes []string, redirectURL url.URL, verifierDID did.DID) (string, error) {
	now := time.Now()
	params := map[string]interface{}{
		scopeParam:        scope,
		redirectURIParam:  redirectURL.String(),
		responseTypeParam: strings.Join(responseTypes, " "),
		clientIDParam:     verifierDID.String(),
		jwt.IssuerKey:     verifierDID.String(),
		jwt.SubjectKey:    verifierDID.String(),
		jwt.JwtIDKey:      uuid.NewString(),
		jwt.IssuedAtKey:   now,
		jwt.NotBeforeKey:  now,
		jwt.ExpirationKey: now.Add(time.Minute),
		"nonce":           uuid.NewString(),
		stateParam:        state,
	}
	for _, responseType := range responseTypes {
		switch responseType {
		case responseTypeIDToken:
			// JWT-VC Presentation profile (SIOPv2)
			params[responseModeParam] = responseModePost
			// TODO: Specifying client_metadata_uri causes Sphereon Wallet to conclude the RP (Nuts Node) does not support SIOPv2 ID1
			// (since client_metadata_uri was specified later, in d11?).
			// Leading to the error message: RP does not support spec version 70, supported versions: 71
			// Which is actually pretty weird, since the URI scheme used is openid-vc: (from JWT VC presentation profile),
			// instead of openid: (from SIOPv2 ID1).
			// params[clientMetadataURIParam] = r.auth.PublicURL().JoinPath(".well-known", "oauth-authorization-server", identifierPath).String()
			// Instead, we specify the registration claim containing the metadata:
			params["registration"] = map[string]interface{}{
				// We can specify loads of metadata fields, but Sphereon Wallet works if we only specify the one(s) below
				"subject_syntax_types_supported": []string{"did:ion", "did:web"},
				"vp_formats": map[string]interface{}{
					"jwt_vc": map[string]interface{}{
						"alg": []string{"ES256K", "EdDSA"},
					},
					"jwt_vp": map[string]interface{}{
						"alg": []string{"ES256K", "EdDSA"},
					},
				},
			}
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
	// Create request JWT: sign Request Object with assertionMethod key of verifier DID
	keyResolver := resolver.PrivateKeyResolver{
		DIDResolver:     r.vdr.Resolver(),
		PrivKeyResolver: r.keyStore,
	}
	//signingKey, err := keyResolver.ResolvePrivateKey(ctx, verifierDID, nil, resolver.NutsSigningKeyType)
	signingKey, err := keyResolver.ResolvePrivateKey(ctx, verifierDID, nil, resolver.Authentication)
	if err != nil {
		return "", fmt.Errorf("failed to resolve signing key (did=%s): %w", verifierDID, err)
	}
	return r.keyStore.SignJWT(ctx, params, nil, signingKey)
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

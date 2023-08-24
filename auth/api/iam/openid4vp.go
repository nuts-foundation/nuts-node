package iam

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"github.com/labstack/echo/v4"
	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/jsonld"
	"github.com/nuts-foundation/nuts-node/vcr"
	"github.com/nuts-foundation/nuts-node/vcr/credential"
	"net/http"
	"net/url"
)

const clientIDParam = "client_id"
const responseTypeParam = "response_type"
const scopeParam = "scope"
const stateParam = "state"
const redirectURIParam = "redirect_uri"
const presentationDefParam = "presentation_definition"
const presentationDefUriParam = "presentation_definition_uri"
const clientMetadataParam = "client_metadata"
const clientMetadataURIParam = "client_metadata_uri"
const clientIDSchemeParam = "client_id_scheme"
const responseModeParam = "response_mode"

// createPresentationRequest creates a new Authorization Request as specified by OpenID4VP: https://openid.net/specs/openid-4-verifiable-presentations-1_0.html.
// It is sent by a verifier to a wallet, to request one or more verifiable credentials as verifiable presentation from the wallet.
func (r *Wrapper) sendPresentationRequest(ctx context.Context, response http.ResponseWriter, scope string,
	redirectURL url.URL, verifierIdentifier url.URL, walletIdentifier url.URL) error {
	// TODO: Lookup wallet metadata for correct authorization endpoint. But for Nuts nodes, we derive it from the walletIdentifier
	authzEndpoint := walletIdentifier.JoinPath("/authorize")
	params := make(map[string]string)
	params[scopeParam] = scope
	params[redirectURIParam] = redirectURL.String()
	// TODO: Check this
	params[clientMetadataURIParam] = verifierIdentifier.JoinPath("/.well-known/openid-wallet-metadata/metadata.xml").String()
	// TODO: use constants from @gsn
	params[responseModeParam] = "direct_post"
	// TODO: use constants from @gsn
	params[responseTypeParam] = "vp_token id_token"
	// TODO: Depending on parameter size, we either use redirect with query parameters or a form post.
	//       For simplicity, we now just query parameters.
	result := AddQueryParams(*authzEndpoint, params)
	response.Header().Add("Location", result.String())
	response.WriteHeader(http.StatusFound)
	return nil
}

// handlePresentationRequest handles an Authorization Request as specified by OpenID4VP: https://openid.net/specs/openid-4-verifiable-presentations-1_0.html.
// It is handled by a wallet, called by a verifier who wants the wallet to present one or more verifiable credentials.
func (r *Wrapper) handlePresentationRequest(params map[string]string, session *Session) (HandleAuthorizeRequestResponseObject, error) {
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
	// TODO: Use constant defined by @gsn
	if params[responseModeParam] != "direct_post" {
		return nil, errors.New("response_mode must be direct_post")
	}

	// TODO: This is the easiest for now, but is this the way?
	// For compatibility, we probably need to support presentation_definition and/or presentation_definition_uri.
	presentationDefinition := r.presentationDefinitions.ByScope(params[scopeParam])
	if presentationDefinition == nil {
		return nil, fmt.Errorf("unsupported scope for presentation exchange: %s", params[scopeParam])
	}

	sessionId := r.sessions.Create(*session)

	// Render HTML
	templateParams := struct {
		SessionID    string
		VerifierName string
		Credentials  []CredentialInfo
	}{
		SessionID: sessionId,
		// TODO: Maybe this should the verifier name be read from registered client metadata?
		VerifierName: ssi.MustParseURI(session.RedirectURI).Host,
	}

	// TODO: https://github.com/nuts-foundation/nuts-node/issues/2357
	// TODO: Retrieve presentation definition
	// TODO: https://github.com/nuts-foundation/nuts-node/issues/2359
	// TODO: Match presentation definition (search for org credential for now)
	searchTerms := []vcr.SearchTerm{
		{IRIPath: jsonld.OrganizationNamePath, Type: vcr.NotNil},
		{IRIPath: jsonld.OrganizationCityPath, Type: vcr.NotNil},
	}
	credentials, err := r.VCR.Search(ctx, searchTerms, false, nil)
	if err != nil {
		return nil, fmt.Errorf("unable to search for credentials: %w", err)
	}
	for _, cred := range credentials {
		var subject []credential.NutsOrganizationCredentialSubject
		if err = cred.UnmarshalCredentialSubject(&subject); err != nil {
			return nil, fmt.Errorf("unable to unmarshal credential: %w", err)
		}
		if len(subject) != 1 {
			continue
		}
		isOwner, _ := r.VDR.IsOwner(ctx, did.MustParseDID(subject[0].ID))
		if isOwner {
			templateParams.Credentials = append(templateParams.Credentials, makeCredentialInfo(cred))
		}
	}

	// TODO: Support multiple languages
	buf := new(bytes.Buffer)
	err = r.templates.ExecuteTemplate(buf, "assets/authz_wallet_en.html", templateParams)
	if err != nil {
		return nil, fmt.Errorf("unable to render authz page: %w", err)
	}
	return HandleAuthorizeRequest200TexthtmlResponse{
		Body:          buf,
		ContentLength: int64(buf.Len()),
	}, nil
}

// handleAuthConsent handles the authorization consent form submission.
func (r *Wrapper) handlePresentationRequestConsent(c echo.Context) error {
	// TODO: Needs authentication?
	var session *Session
	if sessionID := c.Param("sessionID"); sessionID != "" {
		session = r.sessions.Get(sessionID)
	}
	if session == nil {
		return errors.New("invalid session")
	}
	// TODO: create presentation submission
	// TODO: check response mode, and submit accordingly (direct_post)
	return c.Redirect(http.StatusFound, session.CreateRedirectURI(map[string]string{}))
}

func assertParamPresent(params map[string]string, param ...string) error {
	for _, param := range param {
		if len(params[param]) == 0 {
			return fmt.Errorf("%s parameter must be present", param)
		}
	}
	return nil
}

func assertParamNotPresent(params map[string]string, param ...string) error {
	for _, param := range param {
		if len(params[param]) > 0 {
			return fmt.Errorf("%s parameter must not be present", param)
		}
	}
	return nil
}

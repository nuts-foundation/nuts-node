package v0

import (
	"github.com/nuts-foundation/nuts-node/core"
)

var _ protocol = (*openID4VP)(nil)

// openID4VP implements verifiable presentation exchanges as specified by https://openid.net/specs/openid-4-verifiable-presentations-1_0.html.
type openID4VP struct {
}

func (o openID4VP) Routes(router core.EchoRouter) {
	//TODO implement me
	panic("implement me")
}

func (o openID4VP) authzHandlers() []authzHandler {
	return []authzHandler{
		o.handleAuthzRequest,
	}
}

func (o openID4VP) handleAuthzRequest(params map[string]string, session *Session) (bool, error) {
	presentationDef := params["presentation_definition"]
	presentationDefUri := params["presentation_definition_uri"]
	clientIdScheme := params["client_id_scheme"]
	clientMetadata := params["client_metadata"]
	clientMetadataUri := params["client_metadata_uri"]

	if presentationDef == "" &&
		presentationDefUri == "" &&
		clientIdScheme == "" &&
		clientMetadata == "" &&
		clientMetadataUri == "" {
		// Not an OpenID4VP Authorization Request
		return false, nil
	}
	// TODO: Handle the request
	return true, nil
}

func (o openID4VP) grantHandlers() map[string]grantHandler {
	// OpenID4VP does not define new grant types
	return nil
}

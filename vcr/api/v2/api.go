package v2

import (
	"encoding/json"
	"errors"
	"github.com/labstack/echo/v4"
	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/vcr/issuer"
	"github.com/nuts-foundation/nuts-node/vcr/types"
	"net/http"
)

// Wrapper implements the generated interface from oapi-codegen
// It parses and checks the params. Handles errors and returns the appropriate response.
type Wrapper struct {
	CredentialResolver issuer.CredentialSearcher
	VCR                types.VCR
}

// Routes registers the handler to the echo router
func (w *Wrapper) Routes(router core.EchoRouter) {
	RegisterHandlers(router, w)
}

// Preprocess is called just before the API operation itself is invoked.
func (w *Wrapper) Preprocess(operationID string, context echo.Context) {
	context.Set(core.StatusCodeResolverContextKey, w)
	context.Set(core.OperationIDContextKey, operationID)
	context.Set(core.ModuleNameContextKey, "VCR")
}

// IssueVC handles the API request for credential issuing.
func (w Wrapper) IssueVC(ctx echo.Context) error {
	issueRequest := IssueVCRequest{}
	if err := ctx.Bind(&issueRequest); err != nil {
		return err
	}

	var (
		publish bool
		public  bool
	)

	// publish is true by default
	if issueRequest.PublishToNetwork != nil {
		publish = *issueRequest.PublishToNetwork
	} else {
		publish = true
	}

	if issueRequest.Visibility == nil || *issueRequest.Visibility == "" {
		if publish {
			return core.InvalidInputError("visibility must be set when publishing credential")
		}
	} else { // visibility is set
		if !publish {
			return core.InvalidInputError("visibility setting is only allowed when publishing to the network")
		}
		if *issueRequest.Visibility != IssueVCRequestVisibilityPublic && *issueRequest.Visibility != IssueVCRequestVisibilityPrivate {
			return core.InvalidInputError("invalid value for visibility")
		}
	}

	requestedVC := vc.VerifiableCredential{}
	rawRequest, _ := json.Marshal(issueRequest)
	if err := json.Unmarshal(rawRequest, &requestedVC); err != nil {
		return err
	}

	vcCreated, err := w.VCR.Issuer().Issue(requestedVC, publish, public)
	if err != nil {
		return err
	}

	return ctx.JSON(http.StatusOK, vcCreated)
}

// RevokeVC handles the API request for revoking a credential.
func (w Wrapper) RevokeVC(ctx echo.Context, id string) error {
	//TODO implement me
	return errors.New("not yet implemented, use the v1 api")
}

// SearchIssuedVCs handles the API request for searching for issued VCs
func (w *Wrapper) SearchIssuedVCs(ctx echo.Context, params SearchIssuedVCsParams) error {
	issuerDID, err := did.ParseDID(params.Issuer)
	if err != nil {
		return core.InvalidInputError("invalid issuer did: %w", err)
	}
	var subjectID *ssi.URI
	if params.Subject != nil {
		subjectID, err = ssi.ParseURI(*params.Subject)
		if err != nil {
			return core.InvalidInputError("invalid subject id: %w", err)
		}
	}

	credentialType, err := ssi.ParseURI(params.CredentialType)
	if err != nil {
		return core.InvalidInputError("invalid credentialType: %w", err)
	}

	foundVCs, err := w.VCR.Issuer().SearchCredential(ssi.URI{}, *credentialType, *issuerDID, subjectID)
	result := make([]SearchVCResult, len(foundVCs))
	for i, resolvedVC := range foundVCs {
		result[i] = SearchVCResult{VerifiableCredential: resolvedVC}
	}
	if err != nil {
		return err
	}
	return ctx.JSON(http.StatusOK, result)
}

// VerifyVC handles API request to verify a  Verifiable Credential.
func (w *Wrapper) VerifyVC(ctx echo.Context) error {
	requestedVC := VerifiableCredential{}

	if err := ctx.Bind(&requestedVC); err != nil {
		return err
	}

	if err := w.VCR.Validate(requestedVC, false, true, nil); err != nil {
		errMsg := err.Error()
		return ctx.JSON(http.StatusOK, VCVerificationResult{Validity: false, Message: &errMsg})
	}
	return ctx.JSON(http.StatusOK, VCVerificationResult{Validity: true})
}

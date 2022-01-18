package v2

import (
	"encoding/json"
	"github.com/labstack/echo/v4"
	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/vcr/issuer"
	"github.com/nuts-foundation/nuts-node/vcr/types"
	"net/http"
)

type Wrapper struct {
	CredentialResolver issuer.StoreResolver
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

	// public is false by default
	if issueRequest.Visibility != nil {
		if !publish {
			return core.InvalidInputError("visibility setting is only valid when publishing to the network")
		}
		public = *issueRequest.Visibility == IssueVCRequestVisibilityPublic
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

func (w Wrapper) RevokeVC(ctx echo.Context, id string) error {
	//TODO implement me
	panic("implement me")
}

func (w *Wrapper) ResolveIssuedVC(ctx echo.Context, params ResolveIssuedVCParams) error {
	issuerDID, err := did.ParseDID(params.Issuer)
	if err != nil {
		return core.InvalidInputError("invalid issuer did: %w", err)
	}
	subjectID := &ssi.URI{}
	if params.Subject != nil {
		subjectID, err = ssi.ParseURI(*params.Subject)
	}

	foundVCs, err := w.VCR.Issuer().CredentialResolver().SearchCredential(ssi.URI{}, params.CredentialType, *issuerDID, *subjectID)
	if err != nil {
		return err
	}
	return ctx.JSON(http.StatusOK, foundVCs)
}

func (w *Wrapper) VerifyVC(ctx echo.Context) error {
	requestedVC := VerifiableCredential{}

	if err := ctx.Bind(&requestedVC); err != nil {
		return err
	}

	if err := w.VCR.Validate(requestedVC, true, true, nil); err != nil {
		errMsg := err.Error()
		return ctx.JSON(http.StatusOK, VCVerificationResult{Validity: false, Message: &errMsg})
	}
	return ctx.JSON(http.StatusOK, VCVerificationResult{Validity: true})
}

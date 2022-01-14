package v2

import (
	"github.com/labstack/echo/v4"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/vcr"
	"net/http"
)

type Wrapper struct {
	Issuer vcr.Issuer
	VCR    vcr.VCR
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
	requestedVC := IssueVCRequest{}

	if err := ctx.Bind(&requestedVC); err != nil {
		return err
	}

	vcCreated, err := w.Issuer.Issue(requestedVC)
	if err != nil {
		return err
	}

	return ctx.JSON(http.StatusOK, vcCreated)
}

func (w Wrapper) RevokeVC(ctx echo.Context, id string) error {
	//TODO implement me
	panic("implement me")
}

func (w Wrapper) ResolveIssuedVC(ctx echo.Context, id string, params ResolveIssuedVCParams) error {
	//TODO implement me
	panic("implement me")
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

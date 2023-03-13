/*
 * Copyright (C) 2022 Nuts community
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

package v2

import (
	"encoding/json"
	"errors"
	"net/http"

	httpModule "github.com/nuts-foundation/nuts-node/http"

	"github.com/nuts-foundation/nuts-node/jsonld"
	"github.com/nuts-foundation/nuts-node/vcr/credential"
	vcrTypes "github.com/nuts-foundation/nuts-node/vcr/types"
	"github.com/nuts-foundation/nuts-node/vcr/verifier"
	vdrTypes "github.com/nuts-foundation/nuts-node/vdr/types"

	"time"

	"github.com/labstack/echo/v4"
	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/vcr"
	"github.com/nuts-foundation/nuts-node/vcr/issuer"
	"github.com/nuts-foundation/nuts-node/vcr/signature/proof"
)

var clockFn = func() time.Time {
	return time.Now()
}

// Wrapper implements the generated interface from oapi-codegen
// It parses and checks the params. Handles errors and returns the appropriate response.
type Wrapper struct {
	CredentialResolver issuer.CredentialSearcher
	ContextManager     jsonld.JSONLD
	VCR                vcr.VCR
}

// Routes registers the handler to the echo router
func (w *Wrapper) Routes(router core.EchoRouter) {
	RegisterHandlers(router, w)
}

// ResolveStatusCode maps errors returned by this API to specific HTTP status codes.
func (w *Wrapper) ResolveStatusCode(err error) int {
	return core.ResolveStatusCode(err, map[error]int{
		vcrTypes.ErrNotFound:        http.StatusNotFound,
		vdrTypes.ErrServiceNotFound: http.StatusPreconditionFailed,
		vcrTypes.ErrRevoked:         http.StatusConflict,
		vdrTypes.ErrNotFound:        http.StatusBadRequest,
		vdrTypes.ErrKeyNotFound:     http.StatusBadRequest,
		did.ErrInvalidDID:           http.StatusBadRequest,
	})
}

// Preprocess is called just before the API operation itself is invoked.
func (w *Wrapper) Preprocess(operationID string, context echo.Context) {
	httpModule.Preprocess(context, w, vcr.ModuleName, operationID)
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

	// Check param constraints:
	if issueRequest.Visibility == nil || *issueRequest.Visibility == "" {
		if publish {
			return core.InvalidInputError("visibility must be set when publishing credential")
		}
	} else {
		// visibility is set
		// Visibility can only be used when publishing
		if !publish {
			return core.InvalidInputError("visibility setting is only allowed when publishing to the network")
		}
		// Check if the values are in range
		if *issueRequest.Visibility != Public && *issueRequest.Visibility != Private {
			return core.InvalidInputError("invalid value for visibility")
		}
		// Set the actual value
		public = *issueRequest.Visibility == Public
	}

	// Set default context, if not set
	if issueRequest.Context == nil {
		context := credential.NutsV1Context
		issueRequest.Context = &context
	}

	if issueRequest.Type == "" {
		return core.InvalidInputError("missing credential type")
	}

	if issueRequest.CredentialSubject == nil {
		return core.InvalidInputError("missing credentialSubject")
	}

	requestedVC := vc.VerifiableCredential{}
	rawRequest, _ := json.Marshal(issueRequest)
	if err := json.Unmarshal(rawRequest, &requestedVC); err != nil {
		return err
	}

	vcCreated, err := w.VCR.Issuer().Issue(ctx.Request().Context(), requestedVC, publish, public)
	if err != nil {
		return err
	}

	return ctx.JSON(http.StatusOK, vcCreated)
}

// RevokeVC handles the API request for revoking a credential.
func (w Wrapper) RevokeVC(ctx echo.Context, id string) error {
	credentialID, err := ssi.ParseURI(id)
	if err != nil {
		return core.InvalidInputError("invalid credential id: %w", err)
	}

	revocation, err := w.VCR.Issuer().Revoke(ctx.Request().Context(), *credentialID)
	if err != nil {
		return err
	}
	return ctx.JSON(http.StatusOK, revocation)
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
	if err != nil {
		return err
	}
	result, err := w.vcsWithRevocationsToSearchResults(foundVCs)
	if err != nil {
		return err
	}
	return ctx.JSON(http.StatusOK, SearchVCResults{result})
}

// VerifyVC handles API request to verify a  Verifiable Credential.
func (w *Wrapper) VerifyVC(ctx echo.Context) error {
	verifyRequest := VCVerificationRequest{}

	if err := ctx.Bind(&verifyRequest); err != nil {
		return err
	}
	requestedVC := verifyRequest.VerifiableCredential

	allowUntrustedIssuer := false

	if options := verifyRequest.VerificationOptions; options != nil {
		if allowUntrusted := options.AllowUntrustedIssuer; allowUntrusted != nil {
			allowUntrustedIssuer = *allowUntrusted
		}
	}

	if err := w.VCR.Verifier().Verify(requestedVC, allowUntrustedIssuer, true, nil); err != nil {
		errMsg := err.Error()
		return ctx.JSON(http.StatusOK, VCVerificationResult{Validity: false, Message: &errMsg})
	}

	return ctx.JSON(http.StatusOK, VCVerificationResult{Validity: true})
}

// CreateVP handles API request to create a Verifiable Presentation for one or more Verifiable Credentials.
func (w *Wrapper) CreateVP(ctx echo.Context) error {
	request := &CreateVPRequest{}
	if err := ctx.Bind(request); err != nil {
		return err
	}

	if len(request.VerifiableCredentials) == 0 {
		return core.InvalidInputError("verifiableCredentials needs at least 1 item")
	}

	var signerDID *did.DID
	var err error
	if request.SignerDID != nil && len(*request.SignerDID) > 0 {
		signerDID, err = did.ParseDID(*request.SignerDID)
		if err != nil {
			return core.InvalidInputError("invalid signer DID: %w", err)
		}
	}

	created := clockFn()
	var expires *time.Time
	if request.Expires != nil {
		parsedTime, err := time.Parse(time.RFC3339, *request.Expires)
		if err != nil {
			return core.InvalidInputError("invalid value for expires: %w", err)
		}
		if parsedTime.Before(created) {
			return core.InvalidInputError("expires can not lay in the past")
		}
		expires = &parsedTime
	}

	proofOptions := proof.ProofOptions{
		Created:   created,
		Domain:    request.Domain,
		Challenge: request.Challenge,
		Expires:   expires,
	}

	vp, err := w.VCR.Holder().BuildVP(ctx.Request().Context(), request.VerifiableCredentials, proofOptions, signerDID, true)
	if err != nil {
		return err
	}
	return ctx.JSON(http.StatusOK, vp)
}

// VerifyVP handles API request to verify a Verifiable Presentation.
func (w *Wrapper) VerifyVP(ctx echo.Context) error {
	request := &VPVerificationRequest{}
	if err := ctx.Bind(request); err != nil {
		return err
	}

	verifyCredentials := true
	if request.VerifyCredentials != nil {
		verifyCredentials = *request.VerifyCredentials
	}

	var validAt *time.Time
	if request.ValidAt != nil {
		parsedTime, err := time.Parse(time.RFC3339, *request.ValidAt)
		if err != nil {
			return core.InvalidInputError("invalid value for validAt: %w", err)
		}
		validAt = &parsedTime
	}

	verifiedCredentials, err := w.VCR.Verifier().VerifyVP(request.VerifiablePresentation, verifyCredentials, validAt)
	if err != nil {
		if errors.Is(err, verifier.VerificationError{}) {
			msg := err.Error()
			return ctx.JSON(http.StatusOK, VPVerificationResult{Validity: false, Message: &msg})
		}
		return err
	}

	result := VPVerificationResult{Validity: true, Credentials: &verifiedCredentials}
	return ctx.JSON(http.StatusOK, result)
}

// TrustIssuer handles API request to start trusting an issuer of a Verifiable Credential.
func (w *Wrapper) TrustIssuer(ctx echo.Context) error {
	return changeTrust(ctx, func(cType ssi.URI, issuer ssi.URI) error {
		return w.VCR.Trust(cType, issuer)
	})
}

// UntrustIssuer handles API request to stop trusting an issuer of a Verifiable Credential.
func (w *Wrapper) UntrustIssuer(ctx echo.Context) error {
	return changeTrust(ctx, func(cType ssi.URI, issuer ssi.URI) error {
		return w.VCR.Untrust(cType, issuer)
	})
}

// ListTrusted handles API request list all trusted issuers.
func (w *Wrapper) ListTrusted(ctx echo.Context, credentialType string) error {
	uri, err := parseCredentialType(credentialType)
	if err != nil {
		return err
	}

	trusted, err := w.VCR.Trusted(*uri)
	if err != nil {
		return err
	}
	result := make([]string, len(trusted))
	for i, t := range trusted {
		result[i] = t.String()
	}

	return ctx.JSON(http.StatusOK, result)
}

// ListUntrusted handles API request list all untrusted issuers, which have issued Verifiable Credentials.
func (w *Wrapper) ListUntrusted(ctx echo.Context, credentialType string) error {
	uri, err := parseCredentialType(credentialType)
	if err != nil {
		return err
	}

	untrusted, err := w.VCR.Untrusted(*uri)
	if err != nil {
		return err
	}

	result := make([]string, len(untrusted))
	for i, t := range untrusted {
		result[i] = t.String()
	}

	return ctx.JSON(http.StatusOK, result)
}

func (w *Wrapper) vcsWithRevocationsToSearchResults(foundVCs []vc.VerifiableCredential) ([]SearchVCResult, error) {
	result := make([]SearchVCResult, len(foundVCs))
	for i, resolvedVC := range foundVCs {
		var revocation *Revocation
		revocation, err := w.VCR.Verifier().GetRevocation(*resolvedVC.ID)
		if err != nil && !errors.Is(err, verifier.ErrNotFound) {
			return nil, err
		}
		result[i] = SearchVCResult{VerifiableCredential: resolvedVC, Revocation: revocation}
	}
	return result, nil
}

type trustChangeFunc func(ssi.URI, ssi.URI) error

func changeTrust(ctx echo.Context, f trustChangeFunc) error {
	var icc = new(CredentialIssuer)

	if err := ctx.Bind(icc); err != nil {
		return err
	}

	d, err := ssi.ParseURI(icc.Issuer)
	if err != nil {
		return core.InvalidInputError("failed to parse issuer: %w", err)
	}

	cType, err := parseCredentialType(icc.CredentialType)
	if err != nil {
		return err
	}

	if err = f(*cType, *d); err != nil {
		return err
	}

	return ctx.NoContent(http.StatusNoContent)
}

func parseCredentialType(credentialType string) (*ssi.URI, error) {
	uri, err := ssi.ParseURI(credentialType)
	if err != nil {
		return nil, core.InvalidInputError("malformed credential type: %w", err)
	}
	return uri, nil
}

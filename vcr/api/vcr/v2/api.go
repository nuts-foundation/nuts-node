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
	"context"
	"encoding/json"
	"errors"
	"github.com/nuts-foundation/nuts-node/audit"
	"github.com/nuts-foundation/nuts-node/vcr/holder"
	"net/http"

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
	"github.com/nuts-foundation/nuts-node/vcr/signature/proof"
)

var clockFn = func() time.Time {
	return time.Now()
}

var _ StrictServerInterface = (*Wrapper)(nil)

// Wrapper implements the generated interface from oapi-codegen
// It parses and checks the params. Handles errors and returns the appropriate response.
type Wrapper struct {
	ContextManager jsonld.JSONLD
	VCR            vcr.VCR
}

// Routes registers the handler to the echo router
func (w *Wrapper) Routes(router core.EchoRouter) {
	RegisterHandlers(router, NewStrictHandler(w, []StrictMiddlewareFunc{
		func(f StrictHandlerFunc, operationID string) StrictHandlerFunc {
			return func(ctx echo.Context, request interface{}) (response interface{}, err error) {
				ctx.Set(core.OperationIDContextKey, operationID)
				ctx.Set(core.ModuleNameContextKey, vcr.ModuleName)
				ctx.Set(core.StatusCodeResolverContextKey, w)
				return f(ctx, request)
			}
		},
		func(f StrictHandlerFunc, operationID string) StrictHandlerFunc {
			return audit.StrictMiddleware(f, vcr.ModuleName, operationID)
		},
	}))
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

// IssueVC handles the API request for credential issuing.
func (w Wrapper) IssueVC(ctx context.Context, request IssueVCRequestObject) (IssueVCResponseObject, error) {
	var (
		publish bool
		public  bool
	)

	// publish is true by default
	if request.Body.PublishToNetwork != nil {
		publish = *request.Body.PublishToNetwork
	} else {
		publish = true
	}

	// Check param constraints:
	if request.Body.Visibility == nil || *request.Body.Visibility == "" {
		if publish {
			return nil, core.InvalidInputError("visibility must be set when publishing credential")
		}
	} else {
		// visibility is set
		// Visibility can only be used when publishing
		if !publish {
			return nil, core.InvalidInputError("visibility setting is only allowed when publishing to the network")
		}
		// Check if the values are in range
		if *request.Body.Visibility != Public && *request.Body.Visibility != Private {
			return nil, core.InvalidInputError("invalid value for visibility")
		}
		// Set the actual value
		public = *request.Body.Visibility == Public
	}

	// Set default context, if not set
	if request.Body.Context == nil {
		vcContext := credential.NutsV1Context
		request.Body.Context = &vcContext
	}

	if request.Body.Type == "" {
		return nil, core.InvalidInputError("missing credential type")
	}

	if request.Body.CredentialSubject == nil {
		return nil, core.InvalidInputError("missing credentialSubject")
	}

	requestedVC := vc.VerifiableCredential{}
	rawRequest, _ := json.Marshal(*request.Body)
	if err := json.Unmarshal(rawRequest, &requestedVC); err != nil {
		return nil, err
	}

	vcCreated, err := w.VCR.Issuer().Issue(ctx, requestedVC, publish, public)
	if err != nil {
		return nil, err
	}

	return IssueVC200JSONResponse(*vcCreated), nil
}

// RevokeVC handles the API request for revoking a credential.
func (w Wrapper) RevokeVC(ctx context.Context, request RevokeVCRequestObject) (RevokeVCResponseObject, error) {
	credentialID, err := ssi.ParseURI(request.Id)
	if err != nil {
		return nil, core.InvalidInputError("invalid credential id: %w", err)
	}

	revocation, err := w.VCR.Issuer().Revoke(ctx, *credentialID)
	if err != nil {
		return nil, err
	}
	return RevokeVC200JSONResponse(*revocation), nil
}

// SearchIssuedVCs handles the API request for searching for issued VCs
func (w *Wrapper) SearchIssuedVCs(ctx context.Context, request SearchIssuedVCsRequestObject) (SearchIssuedVCsResponseObject, error) {
	issuerDID, err := did.ParseDID(request.Params.Issuer)
	if err != nil {
		return nil, core.InvalidInputError("invalid issuer did: %w", err)
	}
	var subjectID *ssi.URI
	if request.Params.Subject != nil {
		subjectID, err = ssi.ParseURI(*request.Params.Subject)
		if err != nil {
			return nil, core.InvalidInputError("invalid subject id: %w", err)
		}
	}

	credentialType, err := ssi.ParseURI(request.Params.CredentialType)
	if err != nil {
		return nil, core.InvalidInputError("invalid credentialType: %w", err)
	}

	foundVCs, err := w.VCR.Issuer().SearchCredential(*credentialType, *issuerDID, subjectID)
	if err != nil {
		return nil, err
	}
	result, err := w.vcsWithRevocationsToSearchResults(foundVCs)
	if err != nil {
		return nil, err
	}
	return SearchIssuedVCs200JSONResponse(SearchVCResults{result}), nil
}

// VerifyVC handles API request to verify a  Verifiable Credential.
func (w *Wrapper) VerifyVC(ctx context.Context, request VerifyVCRequestObject) (VerifyVCResponseObject, error) {
	requestedVC := request.Body.VerifiableCredential

	allowUntrustedIssuer := false

	if options := request.Body.VerificationOptions; options != nil {
		if allowUntrusted := options.AllowUntrustedIssuer; allowUntrusted != nil {
			allowUntrustedIssuer = *allowUntrusted
		}
	}

	if err := w.VCR.Verifier().Verify(requestedVC, allowUntrustedIssuer, true, nil); err != nil {
		errMsg := err.Error()

		return VerifyVC200JSONResponse(VCVerificationResult{Validity: false, Message: &errMsg}), nil
	}

	return VerifyVC200JSONResponse(VCVerificationResult{Validity: true}), nil
}

// CreateVP handles API request to create a Verifiable Presentation for one or more Verifiable Credentials.
func (w *Wrapper) CreateVP(ctx context.Context, request CreateVPRequestObject) (CreateVPResponseObject, error) {
	if len(request.Body.VerifiableCredentials) == 0 {
		return nil, core.InvalidInputError("verifiableCredentials needs at least 1 item")
	}

	var signerDID *did.DID
	var err error
	if request.Body.SignerDID != nil && len(*request.Body.SignerDID) > 0 {
		signerDID, err = did.ParseDID(*request.Body.SignerDID)
		if err != nil {
			return nil, core.InvalidInputError("invalid signer DID: %w", err)
		}
	}

	created := clockFn()
	var expires *time.Time
	if request.Body.Expires != nil {
		parsedTime, err := time.Parse(time.RFC3339, *request.Body.Expires)
		if err != nil {
			return nil, core.InvalidInputError("invalid value for expires: %w", err)
		}
		if parsedTime.Before(created) {
			return nil, core.InvalidInputError("expires can not lay in the past")
		}
		expires = &parsedTime
	}

	presentationOptions := holder.PresentationOptions{
		ProofOptions: proof.ProofOptions{
			Created:   created,
			Domain:    request.Body.Domain,
			Challenge: request.Body.Challenge,
			Expires:   expires,
		},
	}

	// custom proofPurpose
	if request.Body.ProofPurpose != nil {
		purpose := *request.Body.ProofPurpose
		presentationOptions.ProofOptions.ProofPurpose = string(purpose)
	}

	// pass context and type as ssi.URI
	if request.Body.Context != nil {
		for _, sc := range *request.Body.Context {
			c, err := ssi.ParseURI(sc)
			if err != nil {
				return nil, core.InvalidInputError("invalid value for context: %w", err)
			}
			presentationOptions.AdditionalContexts = append(presentationOptions.AdditionalContexts, *c)
		}
	}
	if request.Body.Type != nil {
		for _, st := range *request.Body.Type {
			t, err := ssi.ParseURI(st)
			if err != nil {
				return nil, core.InvalidInputError("invalid value for type: %w", err)
			}
			presentationOptions.AdditionalTypes = append(presentationOptions.AdditionalTypes, *t)
		}
	}

	vp, err := w.VCR.Wallet().BuildPresentation(ctx, request.Body.VerifiableCredentials, presentationOptions, signerDID, true)
	if err != nil {
		return nil, err
	}
	return CreateVP200JSONResponse(*vp), nil
}

// VerifyVP handles API request to verify a Verifiable Presentation.
func (w *Wrapper) VerifyVP(ctx context.Context, request VerifyVPRequestObject) (VerifyVPResponseObject, error) {
	verifyCredentials := true
	if request.Body.VerifyCredentials != nil {
		verifyCredentials = *request.Body.VerifyCredentials
	}

	var validAt *time.Time
	if request.Body.ValidAt != nil {
		parsedTime, err := time.Parse(time.RFC3339, *request.Body.ValidAt)
		if err != nil {
			return nil, core.InvalidInputError("invalid value for validAt: %w", err)
		}
		validAt = &parsedTime
	}

	verifiedCredentials, err := w.VCR.Verifier().VerifyVP(request.Body.VerifiablePresentation, verifyCredentials, false, validAt)
	if err != nil {
		if errors.Is(err, verifier.VerificationError{}) {
			msg := err.Error()
			return VerifyVP200JSONResponse(VPVerificationResult{Validity: false, Message: &msg}), nil
		}
		return nil, err
	}

	result := VPVerificationResult{Validity: true, Credentials: &verifiedCredentials}
	return VerifyVP200JSONResponse(result), nil
}

// TrustIssuer handles API request to start trusting an issuer of a Verifiable Credential.
func (w *Wrapper) TrustIssuer(ctx context.Context, request TrustIssuerRequestObject) (TrustIssuerResponseObject, error) {
	if err := changeTrust(*request.Body, w.VCR.Trust); err != nil {
		return nil, err
	}
	return TrustIssuer204Response{}, nil
}

// UntrustIssuer handles API request to stop trusting an issuer of a Verifiable Credential.
func (w *Wrapper) UntrustIssuer(ctx context.Context, request UntrustIssuerRequestObject) (UntrustIssuerResponseObject, error) {
	if err := changeTrust(*request.Body, w.VCR.Untrust); err != nil {
		return nil, err
	}
	return UntrustIssuer204Response{}, nil
}

// ListTrusted handles API request list all trusted issuers.
func (w *Wrapper) ListTrusted(ctx context.Context, request ListTrustedRequestObject) (ListTrustedResponseObject, error) {
	result, err := listTrust(request.CredentialType, w.VCR.Trusted)
	if err != nil {
		return nil, err
	}
	return ListTrusted200JSONResponse(result), nil
}

// ListUntrusted handles API request list all untrusted issuers, which have issued Verifiable Credentials.
func (w *Wrapper) ListUntrusted(ctx context.Context, request ListUntrustedRequestObject) (ListUntrustedResponseObject, error) {
	result, err := listTrust(request.CredentialType, w.VCR.Untrusted)
	if err != nil {
		return nil, err
	}
	return ListUntrusted200JSONResponse(result), nil
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

func changeTrust(icc CredentialIssuer, f trustChangeFunc) error {

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

	return nil
}

type listTrustFunc func(credentialType ssi.URI) ([]ssi.URI, error)

func listTrust(credentialType string, f listTrustFunc) ([]string, error) {
	uri, err := parseCredentialType(credentialType)
	if err != nil {
		return nil, err
	}

	list, err := f(*uri)
	if err != nil {
		return nil, err
	}

	result := make([]string, len(list))
	for i, t := range list {
		result[i] = t.String()
	}

	return result, nil
}

func parseCredentialType(credentialType string) (*ssi.URI, error) {
	uri, err := ssi.ParseURI(credentialType)
	if err != nil {
		return nil, core.InvalidInputError("malformed credential type: %w", err)
	}
	return uri, nil
}

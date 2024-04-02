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
	"github.com/nuts-foundation/nuts-node/jsonld"
	"github.com/nuts-foundation/nuts-node/vcr/credential"
	"github.com/nuts-foundation/nuts-node/vcr/holder"
	"github.com/nuts-foundation/nuts-node/vcr/issuer"
	vcrTypes "github.com/nuts-foundation/nuts-node/vcr/types"
	"github.com/nuts-foundation/nuts-node/vcr/verifier"
	"github.com/nuts-foundation/nuts-node/vdr/resolver"
	"net/http"
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
		resolver.ErrServiceNotFound: http.StatusPreconditionFailed,
		vcrTypes.ErrRevoked:         http.StatusConflict,
		resolver.ErrNotFound:        http.StatusBadRequest,
		resolver.ErrKeyNotFound:     http.StatusBadRequest,
		did.ErrInvalidDID:           http.StatusBadRequest,
		vcrTypes.ErrStatusNotFound:  http.StatusBadRequest,
	})
}

// IssueVC handles the API request for credential issuing.
func (w Wrapper) IssueVC(ctx context.Context, request IssueVCRequestObject) (IssueVCResponseObject, error) {
	// validate credential options
	options, err := parseCredentialOptions(request)
	if err != nil {
		return nil, err
	}

	requestedVC := vc.VerifiableCredential{}
	rawRequest, _ := json.Marshal(*request.Body)
	if err := json.Unmarshal(rawRequest, &requestedVC); err != nil {
		return nil, err
	}

	// check required fields
	if len(requestedVC.Type) == 0 {
		return nil, core.InvalidInputError("missing credential type")
	}
	if len(requestedVC.CredentialSubject) == 0 {
		return nil, core.InvalidInputError("missing credentialSubject")
	}

	{ // set missing defaults;
		// TODO add deprecation warning for this?
		// Set default context, if not set
		if len(requestedVC.Context) == 0 {
			requestedVC.Context = []ssi.URI{vc.VCContextV1URI(), credential.NutsV1ContextURI}
		}
	}

	// Copy parsed credential to keep control over what we pass to the issuer,
	// (and also makes unit testing easier since vc.VerifiableCredential has unexported fields that can't be set).
	template := vc.VerifiableCredential{
		Context:           requestedVC.Context,
		Type:              requestedVC.Type,
		Issuer:            requestedVC.Issuer,
		ExpirationDate:    requestedVC.ExpirationDate,
		CredentialSubject: requestedVC.CredentialSubject,
	}

	vcCreated, err := w.VCR.Issuer().Issue(ctx, template, *options)
	if err != nil {
		return nil, err
	}

	return IssueVC200JSONResponse(*vcCreated), nil
}

// parseCredentialOptions extracts returns all options from the request object,
// or an error if the (combination of) options is invalid for the issuer's DID method.
func parseCredentialOptions(request IssueVCRequestObject) (*issuer.CredentialOptions, error) {
	issuerDID, err := did.ParseDID(request.Body.Issuer)
	if err != nil {
		return nil, err
	}

	options := issuer.CredentialOptions{}

	// Set format
	if request.Body.Format != nil {
		options.Format = credential.VCDataModel11CredentialFormat(*request.Body.Format)
	}

	// Valid CredentialOptions:
	// All: Format
	// did:nuts: PublishToNetwork, Visibility
	// did:web: WithStatusList2021Revocation
	switch issuerDID.Method {
	case "nuts":
		options.Publish = true
		if request.Body.PublishToNetwork != nil {
			options.Publish = *request.Body.PublishToNetwork
		}

		// Check param constraints:
		if request.Body.Visibility == nil || *request.Body.Visibility == "" {
			if options.Publish {
				return nil, core.InvalidInputError("visibility must be set when publishing credential")
			}
		} else {
			// visibility is set
			// Visibility can only be used when publishing
			if !options.Publish {
				return nil, core.InvalidInputError("visibility setting is only allowed when publishing to the network")
			}
			// Check if the values are in range
			if *request.Body.Visibility != Public && *request.Body.Visibility != Private {
				return nil, core.InvalidInputError("invalid value for visibility")
			}
			// Set the actual value
			options.Public = *request.Body.Visibility == Public
		}

		// return error for invalid options
		if request.Body.WithStatusList2021Revocation != nil {
			return nil, core.InvalidInputError("illegal option 'withStatusList2021Revocation' requested for issuer's DID method: %s", issuerDID.Method)
		}
	case "web":
		// check if statusList2021Entry should be added
		if request.Body.WithStatusList2021Revocation != nil {
			options.WithStatusListRevocation = *request.Body.WithStatusList2021Revocation
		}
		// non expiring credential MUST set a value for withStatusList2021Revocation
		if request.Body.ExpirationDate == nil && request.Body.WithStatusList2021Revocation == nil {
			return nil, core.InvalidInputError("withStatusList2021Revocation MUST be provided for credentials without expirationDate")
		}
		// return error for invalid options
		if request.Body.PublishToNetwork != nil {
			return nil, core.InvalidInputError("illegal option 'publishToNetwork' requested for issuer's DID method: %s", issuerDID.Method)
		}
		if request.Body.Visibility != nil {
			return nil, core.InvalidInputError("illegal option 'visibility' requested for issuer's DID method: %s", issuerDID.Method)
		}
	default:
		return nil, core.InvalidInputError("unsupported DID method: %s", issuerDID.Method)
	}

	return &options, nil
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

	// did:nuts credential / network revocation
	if revocation != nil {
		return RevokeVC200JSONResponse(*revocation), nil
	}
	// did:web credential / status list revocation
	return RevokeVC204Response{}, nil
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

	if request.Body.Format != nil {
		presentationOptions.Format = string(*request.Body.Format)
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

func (w *Wrapper) LoadVC(ctx context.Context, request LoadVCRequestObject) (LoadVCResponseObject, error) {
	// the actual holder is ignored for now, since we only support a single wallet...
	_, err := did.ParseDID(request.Did)
	if err != nil {
		return nil, core.InvalidInputError("invalid holder DID: %w", err)
	}
	if request.Body == nil {
		return nil, core.InvalidInputError("missing credential in body")
	}
	err = w.VCR.Wallet().Put(ctx, *request.Body)
	if err != nil {
		return nil, err
	}
	return LoadVC204Response{}, nil
}

func (w *Wrapper) GetCredentialsInWallet(ctx context.Context, request GetCredentialsInWalletRequestObject) (GetCredentialsInWalletResponseObject, error) {
	holderDID, err := did.ParseDID(request.Did)
	if err != nil {
		return nil, core.InvalidInputError("invalid holder DID: %w", err)
	}
	credentials, err := w.VCR.Wallet().List(ctx, *holderDID)
	if err != nil {
		return nil, err
	}
	return GetCredentialsInWallet200JSONResponse(credentials), nil
}

func (w *Wrapper) RemoveCredentialFromWallet(ctx context.Context, request RemoveCredentialFromWalletRequestObject) (RemoveCredentialFromWalletResponseObject, error) {
	holderDID, err := did.ParseDID(request.Did)
	if err != nil {
		return nil, core.InvalidInputError("invalid holder DID: %w", err)
	}
	credentialID, err := ssi.ParseURI(request.Id)
	if err != nil {
		return nil, core.InvalidInputError("invalid credential ID: %w", err)
	}
	err = w.VCR.Wallet().Remove(ctx, *holderDID, *credentialID)
	if err != nil {
		return nil, err
	}
	return RemoveCredentialFromWallet204Response{}, nil

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

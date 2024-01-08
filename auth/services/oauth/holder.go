/*
 * Nuts node
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

package oauth

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/auth/client/iam"
	"github.com/nuts-foundation/nuts-node/auth/oauth"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/vcr/holder"
	"github.com/nuts-foundation/nuts-node/vcr/pe"
	"github.com/nuts-foundation/nuts-node/vcr/signature/proof"
	"time"
)

var _ Holder = (*HolderService)(nil)

// ErrNoCredentials is returned when no matching credentials are found in the wallet based on a PresentationDefinition
var ErrNoCredentials = errors.New("no matching credentials")

type HolderService struct {
	strictMode        bool
	httpClientTimeout time.Duration
	httpClientTLS     *tls.Config
	wallet            holder.Wallet
}

// NewHolder returns an implementation of Holder
func NewHolder(wallet holder.Wallet, strictMode bool, httpClientTimeout time.Duration, httpClientTLS *tls.Config) *HolderService {
	return &HolderService{
		wallet:            wallet,
		strictMode:        strictMode,
		httpClientTimeout: httpClientTimeout,
		httpClientTLS:     httpClientTLS,
	}
}

func (v *HolderService) BuildPresentation(ctx context.Context, walletDID did.DID, presentationDefinition pe.PresentationDefinition, acceptedFormats map[string]map[string][]string, nonce string) (*vc.VerifiablePresentation, *pe.PresentationSubmission, error) {
	// get VCs from own wallet
	credentials, err := v.wallet.List(ctx, walletDID)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to retrieve wallet credentials: %w", err)
	}

	expires := time.Now().Add(time.Minute * 15) //todo
	// build VP
	submissionBuilder := presentationDefinition.PresentationSubmissionBuilder()
	submissionBuilder.AddWallet(walletDID, credentials)
	format := pe.ChooseVPFormat(acceptedFormats)
	presentationSubmission, signInstructions, err := submissionBuilder.Build(format)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to build presentation submission: %w", err)
	}
	if signInstructions.Empty() {
		return nil, nil, ErrNoCredentials
	}

	// todo: support multiple wallets
	vp, err := v.wallet.BuildPresentation(ctx, signInstructions[0].VerifiableCredentials, holder.PresentationOptions{
		Format: format,
		ProofOptions: proof.ProofOptions{
			Created:   time.Now(),
			Challenge: &nonce,
			Expires:   &expires,
		},
	}, &walletDID, false)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create verifiable presentation: %w", err)
	}
	return vp, &presentationSubmission, nil
}

func (v *HolderService) ClientMetadata(ctx context.Context, endpoint string) (*oauth.OAuthClientMetadata, error) {
	iamClient := iam.NewHTTPClient(v.strictMode, v.httpClientTimeout, v.httpClientTLS)

	metadata, err := iamClient.ClientMetadata(ctx, endpoint)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve remote OAuth Authorization Server metadata: %w", err)
	}
	return metadata, nil
}

func (v *HolderService) PostError(ctx context.Context, auth2Error oauth.OAuth2Error, verifierResponseURI string) (string, error) {
	iamClient := iam.NewHTTPClient(v.strictMode, v.httpClientTimeout, v.httpClientTLS)

	redirectURL, err := iamClient.PostError(ctx, auth2Error, verifierResponseURI)
	if err != nil {
		return "", fmt.Errorf("failed to post error to verifier: %w", err)
	}

	return redirectURL, nil
}

func (v *HolderService) PostAuthorizationResponse(ctx context.Context, vp vc.VerifiablePresentation, presentationSubmission pe.PresentationSubmission, verifierResponseURI string) (string, error) {
	iamClient := iam.NewHTTPClient(v.strictMode, v.httpClientTimeout, v.httpClientTLS)

	redirectURL, err := iamClient.PostAuthorizationResponse(ctx, vp, presentationSubmission, verifierResponseURI)
	if err == nil {
		return redirectURL, nil
	}

	return "", fmt.Errorf("failed to post authorization response to verifier: %w", err)
}

func (s *HolderService) PresentationDefinition(ctx context.Context, presentationDefinitionParam string) (*pe.PresentationDefinition, error) {
	presentationDefinitionURL, err := core.ParsePublicURL(presentationDefinitionParam, s.strictMode)
	if err != nil {
		return nil, err
	}

	iamClient := iam.NewHTTPClient(s.strictMode, s.httpClientTimeout, s.httpClientTLS)
	presentationDefinition, err := iamClient.PresentationDefinition(ctx, *presentationDefinitionURL)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve presentation definition: %w", err)
	}
	return presentationDefinition, nil
}

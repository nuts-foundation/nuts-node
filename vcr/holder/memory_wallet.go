/*
 * Copyright (C) 2024 Nuts community
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

package holder

import (
	"context"
	"errors"
	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/vcr/pe"
	"github.com/nuts-foundation/nuts-node/vdr/resolver"
	"github.com/piprate/json-gold/ld"
)

func NewMemoryWallet(documentLoader ld.DocumentLoader, keyResolver resolver.KeyResolver, keyStore crypto.KeyStore,
	credentials map[did.DID][]vc.VerifiableCredential) Wallet {
	return &memoryWallet{
		credentials:    credentials,
		documentLoader: documentLoader,
		keyResolver:    keyResolver,
		keyStore:       keyStore,
	}
}

type memoryWallet struct {
	credentials    map[did.DID][]vc.VerifiableCredential
	documentLoader ld.DocumentLoader
	keyResolver    resolver.KeyResolver
	keyStore       crypto.KeyStore
}

var _ Wallet = (*memoryWallet)(nil)

func (m memoryWallet) BuildPresentation(ctx context.Context, credentials []vc.VerifiableCredential, options PresentationOptions, signerDID *did.DID, validateVC bool) (*vc.VerifiablePresentation, error) {
	return presenter{
		documentLoader: m.documentLoader,
		keyStore:       m.keyStore,
		keyResolver:    m.keyResolver,
	}.buildPresentation(ctx, signerDID, credentials, options)
}

func (m memoryWallet) BuildSubmission(ctx context.Context, walletDID did.DID, presentationDefinition pe.PresentationDefinition, acceptedFormats map[string]map[string][]string, params BuildParams) (*vc.VerifiablePresentation, *pe.PresentationSubmission, error) {
	return presenter{
		documentLoader: m.documentLoader,
		keyStore:       m.keyStore,
		keyResolver:    m.keyResolver,
	}.buildSubmission(ctx, walletDID, m.credentials[walletDID], presentationDefinition, acceptedFormats, params)
}

func (m memoryWallet) List(_ context.Context, holderDID did.DID) ([]vc.VerifiableCredential, error) {
	return m.credentials[holderDID], nil
}

func (m memoryWallet) Remove(_ context.Context, _ did.DID, _ ssi.URI) error {
	return errors.New("memory wallet is read-only")
}

func (m memoryWallet) Put(_ context.Context, _ ...vc.VerifiableCredential) error {
	return errors.New("memory wallet is read-only")
}

func (m memoryWallet) IsEmpty() (bool, error) {
	return len(m.credentials) == 0, nil
}

func (m memoryWallet) Diagnostics() []core.DiagnosticResult {
	return nil
}

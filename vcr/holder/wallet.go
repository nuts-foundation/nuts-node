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

package holder

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/go-stoabs"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/jsonld"
	"github.com/nuts-foundation/nuts-node/vcr/log"
	"github.com/nuts-foundation/nuts-node/vcr/signature"
	"github.com/nuts-foundation/nuts-node/vcr/signature/proof"
	"github.com/nuts-foundation/nuts-node/vcr/verifier"
	vdr "github.com/nuts-foundation/nuts-node/vdr/types"
	"sync/atomic"
)

type wallet struct {
	keyResolver         vdr.KeyResolver
	documentOwner       vdr.DocumentOwner
	keyStore            crypto.KeyStore
	verifier            verifier.Verifier
	jsonldManager       jsonld.JSONLD
	walletStore         stoabs.KVStore
	numCredentials      *atomic.Uint32
	numCredentialsStale *atomic.Bool
}

// New creates a new Wallet.
func New(
	keyResolver vdr.KeyResolver, documentOwner vdr.DocumentOwner, keyStore crypto.KeyStore, verifier verifier.Verifier,
	jsonldManager jsonld.JSONLD, walletStore stoabs.KVStore) Wallet {
	numCredentialsStale := &atomic.Bool{}
	numCredentialsStale.Store(true)
	return &wallet{
		documentOwner:       documentOwner,
		keyResolver:         keyResolver,
		keyStore:            keyStore,
		verifier:            verifier,
		jsonldManager:       jsonldManager,
		walletStore:         walletStore,
		numCredentials:      &atomic.Uint32{},
		numCredentialsStale: numCredentialsStale,
	}
}

func (h wallet) BuildPresentation(ctx context.Context, credentials []vc.VerifiableCredential, options PresentationOptions, signerDID *did.DID, validateVC bool) (*vc.VerifiablePresentation, error) {
	var err error
	if signerDID == nil {
		signerDID, err = h.resolveSubjectDID(credentials)
		if err != nil {
			return nil, fmt.Errorf("unable to resolve signer DID from VCs for creating VP: %w", err)
		}
	}

	kid, _, err := h.keyResolver.ResolveKey(*signerDID, nil, vdr.NutsSigningKeyType)
	if err != nil {
		return nil, fmt.Errorf("unable to resolve assertion key for signing VP (did=%s): %w", *signerDID, err)
	}
	key, err := h.keyStore.Resolve(ctx, kid.String())
	if err != nil {
		return nil, fmt.Errorf("unable to resolve assertion key from key store for signing VP (did=%s): %w", *signerDID, err)
	}

	if validateVC {
		for _, cred := range credentials {
			err := h.verifier.Validate(cred, &options.ProofOptions.Created)
			if err != nil {
				return nil, core.InvalidInputError("invalid credential (id=%s): %w", cred.ID, err)
			}
		}
	}

	ldContext := []ssi.URI{VerifiableCredentialLDContextV1, signature.JSONWebSignature2020Context}
	ldContext = append(ldContext, options.AdditionalContexts...)
	types := []ssi.URI{VerifiablePresentationLDType}
	types = append(types, options.AdditionalTypes...)

	unsignedVP := &vc.VerifiablePresentation{
		Context:              ldContext,
		Type:                 types,
		VerifiableCredential: credentials,
	}

	// Convert to map[string]interface{} for signing
	documentBytes, err := unsignedVP.MarshalJSON()
	if err != nil {
		return nil, err
	}
	var document proof.Document
	err = json.Unmarshal(documentBytes, &document)
	if err != nil {
		return nil, err
	}

	// TODO: choose between different proof types (JWT or LD-Proof)
	signingResult, err := proof.
		NewLDProof(options.ProofOptions).
		Sign(ctx, document, signature.JSONWebSignature2020{ContextLoader: h.jsonldManager.DocumentLoader(), Signer: h.keyStore}, key)
	if err != nil {
		return nil, fmt.Errorf("unable to sign VP with LD proof: %w", err)
	}

	var signedVP vc.VerifiablePresentation
	signedVPData, _ := json.Marshal(signingResult)
	err = json.Unmarshal(signedVPData, &signedVP)
	if err != nil {
		return nil, err
	}

	return &signedVP, nil
}

func (h wallet) Put(ctx context.Context, credential vc.VerifiableCredential) error {
	subjectDID, err := h.resolveSubjectDID([]vc.VerifiableCredential{credential})
	if err != nil {
		return err
	}
	err = h.walletStore.WriteShelf(ctx, subjectDID.String(), func(writer stoabs.Writer) error {
		data, _ := credential.MarshalJSON()
		h.numCredentialsStale.Store(true)
		return writer.Put(stoabs.BytesKey(credential.ID.String()), data)
	})
	if err != nil {
		return fmt.Errorf("unable to store credential: %w", err)
	}
	return nil
}

func (h wallet) List(ctx context.Context, holderDID did.DID) ([]vc.VerifiableCredential, error) {
	var result []vc.VerifiableCredential
	err := h.walletStore.ReadShelf(ctx, holderDID.String(), func(reader stoabs.Reader) error {
		return reader.Iterate(func(key stoabs.Key, value []byte) error {
			var cred vc.VerifiableCredential
			err := json.Unmarshal(value, &cred)
			if err != nil {
				return fmt.Errorf("unable to unmarshal credential %s: %w", string(key.Bytes()), err)
			}
			result = append(result, cred)
			return nil
		}, stoabs.BytesKey{})
	})
	if err != nil {
		return nil, fmt.Errorf("unable to list credentials: %w", err)
	}
	return result, nil
}

func (h wallet) Diagnostics() []core.DiagnosticResult {
	// The number of credentials is cached, since it could be an expensive operation if there's many (hundreds/thousands) DIDs owned by
	// the node, since it's an O(n)-complexity operation at best (worse if each DID has multiple credentials).
	// The cache is marked stale, and thus refreshed on next diagnostics invocation, when a credential is written to te wallet.
	ctx := context.Background()
	var count int
	if h.numCredentialsStale.CompareAndSwap(true, false) {
		ownedDIDs, err := h.documentOwner.ListOwned(ctx)
		if err != nil {
			log.Logger().WithError(err).Warn("unable to list owned DIDs")
		}
		for _, ownedDID := range ownedDIDs {
			err := h.walletStore.ReadShelf(ctx, ownedDID.String(), func(reader stoabs.Reader) error {
				return reader.Iterate(func(_ stoabs.Key, _ []byte) error {
					count++
					return nil
				}, stoabs.BytesKey{})
			})
			if err != nil {
				log.Logger().WithError(err).Warnf("unable to count credentials in wallet for DID: %s", ownedDID)
			}
		}
		h.numCredentials.Store(uint32(count))
	}

	return []core.DiagnosticResult{
		core.GenericDiagnosticResult{
			Title:   "credential_count",
			Outcome: int(h.numCredentials.Load()),
		},
	}
}

func (h wallet) resolveSubjectDID(credentials []vc.VerifiableCredential) (*did.DID, error) {
	type credentialSubject struct {
		ID did.DID `json:"id"`
	}
	var subjectID did.DID
	for _, credential := range credentials {
		var subjects []credentialSubject
		err := credential.UnmarshalCredentialSubject(&subjects)
		if err != nil || len(subjects) != 1 {
			return nil, errors.New("not all VCs contain credentialSubject.id")
		}
		subject := subjects[0]
		if !subjectID.Empty() && !subjectID.Equals(subject.ID) {
			return nil, errors.New("not all VCs have the same credentialSubject.id")
		}
		subjectID = subject.ID
	}

	if subjectID.Empty() {
		return nil, errors.New("could not resolve subject DID from VCs")
	}

	return &subjectID, nil
}

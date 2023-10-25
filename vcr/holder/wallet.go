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
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/lestrrat-go/jwx/jws"
	"github.com/lestrrat-go/jwx/jwt"
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
	"github.com/nuts-foundation/nuts-node/vdr/resolver"
	"time"
)

const statsShelf = "stats"

var credentialCountStatsKey = stoabs.BytesKey("credential_count")

type wallet struct {
	keyResolver   resolver.KeyResolver
	keyStore      crypto.KeyStore
	verifier      verifier.Verifier
	jsonldManager jsonld.JSONLD
	walletStore   stoabs.KVStore
}

// New creates a new Wallet.
func New(
	keyResolver resolver.KeyResolver, keyStore crypto.KeyStore, verifier verifier.Verifier, jsonldManager jsonld.JSONLD,
	walletStore stoabs.KVStore) Wallet {
	return &wallet{
		keyResolver:   keyResolver,
		keyStore:      keyStore,
		verifier:      verifier,
		jsonldManager: jsonldManager,
		walletStore:   walletStore,
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

	kid, _, err := h.keyResolver.ResolveKey(*signerDID, nil, resolver.NutsSigningKeyType)
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

	switch options.Format {
	case JWTPresentationFormat:
		return h.buildJWTPresentation(ctx, *signerDID, credentials, options, key)
	case "":
		fallthrough
	case JSONLDPresentationFormat:
		return h.buildJSONLDPresentation(ctx, credentials, options, key)
	default:
		return nil, errors.New("unsupported presentation proof format")
	}
}

// buildJWTPresentation builds a JWT presentation according to https://www.w3.org/TR/vc-data-model/#json-web-token
func (h wallet) buildJWTPresentation(ctx context.Context, subjectDID did.DID, credentials []vc.VerifiableCredential, options PresentationOptions, key crypto.Key) (*vc.VerifiablePresentation, error) {
	headers := map[string]interface{}{
		jws.TypeKey: "JWT",
	}
	claims := map[string]interface{}{
		jwt.IssuerKey:  subjectDID.String(),
		jwt.SubjectKey: subjectDID.String(),
		"vp": vc.VerifiablePresentation{
			Context:              append([]ssi.URI{VerifiableCredentialLDContextV1}, options.AdditionalContexts...),
			Type:                 append([]ssi.URI{VerifiablePresentationLDType}, options.AdditionalTypes...),
			VerifiableCredential: credentials,
		},
	}
	if options.ProofOptions.Created.IsZero() {
		claims[jwt.NotBeforeKey] = time.Now().Unix()
	} else {
		claims[jwt.NotBeforeKey] = int(options.ProofOptions.Created.Unix())
	}
	if options.ProofOptions.Expires != nil {
		claims[jwt.ExpirationKey] = int(options.ProofOptions.Expires.Unix())
	}
	token, err := h.keyStore.SignJWT(ctx, claims, headers, key)
	if err != nil {
		return nil, fmt.Errorf("unable to sign JWT presentation: %w", err)
	}
	return vc.ParseVerifiablePresentation(token)
}

func (h wallet) buildJSONLDPresentation(ctx context.Context, credentials []vc.VerifiableCredential, options PresentationOptions, key crypto.Key) (*vc.VerifiablePresentation, error) {
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
	resultJSON, _ := json.Marshal(signingResult)
	return vc.ParseVerifiablePresentation(string(resultJSON))
}

func (h wallet) Put(ctx context.Context, credentials ...vc.VerifiableCredential) error {
	err := h.walletStore.Write(ctx, func(tx stoabs.WriteTx) error {
		stats := tx.GetShelfWriter(statsShelf)
		var newCredentials uint32
		for _, credential := range credentials {
			subjectDID, err := h.resolveSubjectDID([]vc.VerifiableCredential{credential})
			if err != nil {
				return fmt.Errorf("unable to resolve subject DID from VC %s: %w", credential.ID, err)
			}
			walletKey := stoabs.BytesKey(credential.ID.String())
			// First check if the VC doesn't already exist; otherwise stats will be incorrect
			walletShelf := tx.GetShelfWriter(subjectDID.String())
			_, err = walletShelf.Get(walletKey)
			if err == nil {
				// Already exists
				continue
			} else if !errors.Is(err, stoabs.ErrKeyNotFound) {
				// Other error
				return fmt.Errorf("unable to check if credential %s already exists: %w", credential.ID, err)
			}
			// Write credential
			data, _ := credential.MarshalJSON()
			err = walletShelf.Put(walletKey, data)
			if err != nil {
				return fmt.Errorf("unable to store credential %s: %w", credential.ID, err)
			}
			newCredentials++
		}
		// Update stats
		currentCount, err := h.readCredentialCount(stats)
		if err != nil {
			return fmt.Errorf("unable to read wallet credential count: %w", err)
		}
		return stats.Put(credentialCountStatsKey, binary.BigEndian.AppendUint32([]byte{}, currentCount+newCredentials))
	}, stoabs.WithWriteLock()) // lock required for stats consistency
	if err != nil {
		return fmt.Errorf("unable to store credential(s): %w", err)
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
	ctx := context.Background()
	var count uint32
	var err error
	err = h.walletStore.Read(ctx, func(tx stoabs.ReadTx) error {
		count, err = h.readCredentialCount(tx.GetShelfReader(statsShelf))
		return err
	})
	if err != nil {
		log.Logger().WithError(err).Warn("unable to read credential count in wallet")
	}
	return []core.DiagnosticResult{
		core.GenericDiagnosticResult{
			Title:   "credential_count",
			Outcome: int(count),
		},
	}
}

func (h wallet) IsEmpty() (bool, error) {
	ctx := context.Background()
	var count uint32
	var err error
	err = h.walletStore.Read(ctx, func(tx stoabs.ReadTx) error {
		count, err = h.readCredentialCount(tx.GetShelfReader(statsShelf))
		return err
	})
	return count == 0, err
}

func (h wallet) resolveSubjectDID(credentials []vc.VerifiableCredential) (*did.DID, error) {
	var subjectID did.DID
	for _, credential := range credentials {
		sid, err := credential.SubjectDID()
		if err != nil {
			return nil, err
		}
		if !subjectID.Empty() && !subjectID.Equals(*sid) {
			return nil, errors.New("not all VCs have the same credentialSubject.id")
		}
		subjectID = *sid
	}

	if subjectID.Empty() {
		return nil, errors.New("could not resolve subject DID from VCs")
	}

	return &subjectID, nil
}

func (h wallet) readCredentialCount(statsShelf stoabs.Reader) (uint32, error) {
	countBytes, err := statsShelf.Get(credentialCountStatsKey)
	if errors.Is(err, stoabs.ErrKeyNotFound) {
		// No stats yet
		countBytes = make([]byte, 4)
	} else if err != nil {
		return 0, fmt.Errorf("error reading credential count for wallet: %w", err)
	}
	return binary.BigEndian.Uint32(countBytes), nil
}

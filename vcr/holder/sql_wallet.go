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
	"errors"
	"fmt"
	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/audit"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/jsonld"
	"github.com/nuts-foundation/nuts-node/storage"
	"github.com/nuts-foundation/nuts-node/vcr/credential"
	"github.com/nuts-foundation/nuts-node/vcr/credential/store"
	"github.com/nuts-foundation/nuts-node/vcr/log"
	"github.com/nuts-foundation/nuts-node/vcr/pe"
	"github.com/nuts-foundation/nuts-node/vcr/types"
	"github.com/nuts-foundation/nuts-node/vcr/verifier"
	"github.com/nuts-foundation/nuts-node/vdr/resolver"
	"gorm.io/gorm"
	"gorm.io/gorm/schema"
	"time"
)

type sqlWallet struct {
	keyResolver   resolver.KeyResolver
	keyStore      crypto.KeyStore
	verifier      verifier.Verifier
	jsonldManager jsonld.JSONLD
	walletStore   walletStore
}

// NewSQLWallet creates a new Wallet which stores credentials in a SQL database.
func NewSQLWallet(
	keyResolver resolver.KeyResolver, keyStore crypto.KeyStore, verifier verifier.Verifier, jsonldManager jsonld.JSONLD,
	storageEngine storage.Engine) Wallet {
	return &sqlWallet{
		keyResolver:   keyResolver,
		keyStore:      keyStore,
		verifier:      verifier,
		jsonldManager: jsonldManager,
		walletStore:   walletStore{db: storageEngine.GetSQLDatabase()},
	}
}

// BuildParams contains the parameters that will be used for building the verifiable presentation
// this includes both parameters for the proof and general requirements.
type BuildParams struct {
	// Audience is used to fill the audience field in the proof
	Audience string
	// DIDMethods is a list of DID methods that the verifier supports for presentation/credential validation
	DIDMethods []string
	// Expires is the expiration time of the presentation
	Expires time.Time
	// Format is a map of format designations that the verifier supports for the presentation
	Format map[string]map[string][]string
	// Nonce is used to fill the nonce/challenge field in the proof
	Nonce string
}

func (h sqlWallet) BuildSubmission(ctx context.Context, walletDIDs []did.DID, credentials map[did.DID][]vc.VerifiableCredential, presentationDefinition pe.PresentationDefinition, params BuildParams) (*vc.VerifiablePresentation, *pe.PresentationSubmission, error) {
	if credentials == nil {
		credentials = make(map[did.DID][]vc.VerifiableCredential)
	}

	// get VCs from own wallet(s)
	for _, walletDID := range walletDIDs {
		creds, err := h.List(ctx, walletDID)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to retrieve wallet credentials: %w", err)
		}
		// check if the issuer/credentialSubject is in the list of verifier DID methods.
		credentials[walletDID] = append(credentials[walletDID], credential.FilterOnDIDMethod(creds, params.DIDMethods)...)
	}
	return presenter{
		documentLoader: h.jsonldManager.DocumentLoader(),
		signer:         h.keyStore,
		keyResolver:    h.keyResolver,
	}.buildSubmission(ctx, credentials, presentationDefinition, params)
}

func (h sqlWallet) BuildPresentation(ctx context.Context, credentials []vc.VerifiableCredential, options PresentationOptions, signerDID *did.DID, validateVC bool) (*vc.VerifiablePresentation, error) {
	if validateVC {
		for _, cred := range credentials {
			err := h.verifier.VerifySignature(cred, &options.ProofOptions.Created)
			if err != nil {
				return nil, core.InvalidInputError("invalid credential (id=%s): %w", cred.ID, err)
			}
		}
	}
	return presenter{
		documentLoader: h.jsonldManager.DocumentLoader(),
		signer:         h.keyStore,
		keyResolver:    h.keyResolver,
	}.buildPresentation(ctx, signerDID, credentials, options)
}

func (h sqlWallet) Put(_ context.Context, credentials ...vc.VerifiableCredential) error {
	return h.walletStore.put(credentials...)
}

func (h sqlWallet) List(_ context.Context, holderDID did.DID) ([]vc.VerifiableCredential, error) {
	credentials, err := h.walletStore.list(holderDID)
	if err != nil {
		return nil, err
	}
	// now validate credentials and remove invalid ones
	validCredentials := make([]vc.VerifiableCredential, 0, len(credentials))
	for _, credential := range credentials {
		// we only want to check expiration and revocation status
		if err = h.verifier.Verify(credential, true, false, nil); err == nil {
			validCredentials = append(validCredentials, credential)
		} else if !errors.Is(err, types.ErrCredentialNotValidAtTime) && !errors.Is(err, types.ErrRevoked) {
			// a possible technical error has occurred that should be logged.
			log.Logger().WithError(err).WithField(core.LogFieldCredentialID, credential.ID).Warn("unable to verify credential")
		}
	}

	return validCredentials, nil
}

func (h sqlWallet) Remove(ctx context.Context, holderDID did.DID, credentialID ssi.URI) error {
	err := h.walletStore.remove(holderDID, credentialID)
	if err == nil {
		audit.Log(ctx, log.Logger(), audit.VerifiableCredentialRemovedEvent).
			WithField(core.LogFieldCredentialID, credentialID).
			WithField(core.LogFieldWalletDID, holderDID).
			Info("Removed credential from wallet")
	}
	return err
}

func (h sqlWallet) Diagnostics() []core.DiagnosticResult {
	count, err := h.walletStore.count()
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

func (h sqlWallet) IsEmpty() (bool, error) {
	count, err := h.walletStore.count()
	return count == 0, err
}

var _ schema.Tabler = (*walletRecord)(nil)

type walletRecord struct {
	HolderDID    string                 `gorm:"primaryKey;column:holder_did"`
	CredentialID string                 `gorm:"primaryKey"`
	Credential   store.CredentialRecord `gorm:"foreignKey:CredentialID;references:ID"`
}

func (walletRecord) TableName() string {
	return "wallet_credential"
}

type walletStore struct {
	db *gorm.DB
}

func (s walletStore) count() (int64, error) {
	var count int64
	err := s.db.Model(walletRecord{}).Count(&count).Error
	return count, err
}

func (s walletStore) list(holderDID did.DID) ([]vc.VerifiableCredential, error) {
	var records []walletRecord
	err := s.db.Model(walletRecord{}).Preload("Credential").Where("holder_did = ?", holderDID.String()).Find(&records).Error
	if err != nil {
		return nil, err
	}
	results := make([]vc.VerifiableCredential, 0)
	for _, record := range records {
		verifiableCredential, err := vc.ParseVerifiableCredential(record.Credential.Raw)
		if err != nil {
			return nil, fmt.Errorf("unable to unmarshal credential %s: %w", record.CredentialID, err)
		}
		results = append(results, *verifiableCredential)
	}
	return results, nil
}

func (s walletStore) put(credentials ...vc.VerifiableCredential) error {
	return s.db.Transaction(func(tx *gorm.DB) error {
		for _, curr := range credentials {
			subjectDID, err := curr.SubjectDID()
			if err != nil {
				return fmt.Errorf("unable to resolve subject DID from VC %s: %w", curr.ID, err)
			}
			record, err := store.CredentialStore{}.Store(tx, curr)
			if err != nil {
				return err
			}
			if err := tx.FirstOrCreate(&walletRecord{
				HolderDID:    subjectDID.String(),
				CredentialID: record.ID,
			}).Error; err != nil {
				return err
			}
		}
		return nil
	})
}

func (s walletStore) remove(holderDID did.DID, credentialID ssi.URI) error {
	result := s.db.Where("holder_did = ? AND credential_id = ?", holderDID.String(), credentialID.String()).Delete(&walletRecord{})
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return types.ErrNotFound
	}
	return nil
}

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

package orm

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/jsonld"
	"gorm.io/gorm/schema"
)

// DidDocument is the gorm representation of the did_document_version table
type DidDocument struct {
	ID        string `gorm:"primaryKey"`
	DidID     string `gorm:"column:did"`
	DID       DID    `gorm:"foreignKey:DidID;references:ID"`
	CreatedAt int64  `gorm:"autoCreateTime"` // auto set unix timestamp iff 0; i.e., when DID is being created
	// UpdatedAt is the (unix) timestamp when the document was updated (and this version was thus created)
	// Also used to purge DID document changes that haven't been committed within a certain time frame
	UpdatedAt           int64 `gorm:"autoUpdateTime:false"`
	Version             int
	VerificationMethods []VerificationMethod `gorm:"many2many:did_document_to_verification_method"`
	Services            []Service            `gorm:"many2many:did_document_to_service"`
	// Raw contains the DID Document as generated by the specific method, important for hashing.
	Raw string
}

func (d DidDocument) TableName() string {
	return "did_document_version"
}

var _ schema.Tabler = (*DID)(nil)

func (sqlDoc DidDocument) ToDIDDocument() (did.Document, error) {
	if len(sqlDoc.Raw) > 0 {
		document := did.Document{}
		err := json.Unmarshal([]byte(sqlDoc.Raw), &document)
		if err != nil {
			return did.Document{}, err
		}
		return document, nil
	}
	return sqlDoc.GenerateDIDDocument()
}

func (sqlDoc DidDocument) GenerateDIDDocument() (did.Document, error) {
	id, _ := did.ParseDID(sqlDoc.DID.ID)
	document := did.Document{
		Context: []interface{}{
			did.DIDContextV1URI(),
			jsonld.JWS2020ContextV1URI(),
		},
		ID: *id,
	}
	for _, sqlVM := range sqlDoc.VerificationMethods {
		verificationMethod := did.VerificationMethod{}
		err := json.Unmarshal(sqlVM.Data, &verificationMethod)
		if err != nil {
			return document, err
		}

		if AssertionMethodUsage.Is(DIDKeyFlags(sqlVM.KeyTypes)) {
			document.AddAssertionMethod(&verificationMethod)
		}
		if AuthenticationUsage.Is(DIDKeyFlags(sqlVM.KeyTypes)) {
			document.AddAuthenticationMethod(&verificationMethod)
		}
		if KeyAgreementUsage.Is(DIDKeyFlags(sqlVM.KeyTypes)) {
			document.AddKeyAgreement(&verificationMethod)
		}
		if CapabilityDelegationUsage.Is(DIDKeyFlags(sqlVM.KeyTypes)) {
			document.AddCapabilityDelegation(&verificationMethod)
		}
		if CapabilityInvocationUsage.Is(DIDKeyFlags(sqlVM.KeyTypes)) {
			document.AddCapabilityInvocation(&verificationMethod)
		}
	}
	for _, sqlService := range sqlDoc.Services {
		service := did.Service{}
		err := json.Unmarshal(sqlService.Data, &service)
		if err != nil {
			return document, err
		}
		document.Service = append(document.Service, service)
	}

	return document, nil
}

// MigrationDocument is used to convert a did.Document + metadata to a DidDocument.
// DEPRECATED: only intended to migrate owned did:nuts to SQL storage.
type MigrationDocument struct {
	// Raw contains the did.Document in bytes. For did:nuts this is must be equal to the payload in the network transaction.
	Raw     []byte
	Created time.Time
	Updated time.Time
	Version int
}

// ToORMDocument converts the Raw document to a DidDocument. Generates a new DidDocument.ID
func (migration MigrationDocument) ToORMDocument(subject string) (DidDocument, error) {
	doc := new(did.Document)
	err := json.Unmarshal(migration.Raw, doc)
	if err != nil {
		return DidDocument{}, err
	}

	// generate DB documentID
	documentID := uuid.New().String()

	// convert []did.VerificationMethod to []VerificationMethod
	vms := make([]VerificationMethod, len(doc.VerificationMethod))
	for i, vm := range doc.VerificationMethod {
		vmAsJson, _ := json.Marshal(*vm)
		vms[i] = VerificationMethod{
			ID:       vm.ID.String(),
			KeyTypes: VerificationMethodKeyType(verificationMethodToKeyFlags(*doc, vm)),
			Data:     vmAsJson,
		}
	}

	// convert []did.Service to []Service
	services := make([]Service, len(doc.Service))
	for i, service := range doc.Service {
		asJson, _ := json.Marshal(service)
		services[i] = Service{
			ID:   service.ID.String(),
			Data: asJson,
		}
	}

	// DID
	subjectDID := DID{
		ID:      doc.ID.String(),
		Subject: subject,
	}

	// return document
	return DidDocument{
		ID:                  documentID,
		DidID:               doc.ID.String(),
		DID:                 subjectDID,
		CreatedAt:           migration.Created.Unix(),
		UpdatedAt:           migration.Updated.Unix(),
		Version:             migration.Version,
		VerificationMethods: vms,
		Services:            services,
		Raw:                 string(migration.Raw),
	}, nil
}

package sql

import (
	"errors"
	"fmt"
	"github.com/nuts-foundation/go-did/did"
	"gorm.io/gorm"
	"gorm.io/gorm/schema"
)

// DIDDocument is the gorm representation of the DID table
type DIDDocument struct {
	ID                  string `gorm:"primaryKey"`
	DidID               string `gorm:"column:did"`
	DID                 DID    `gorm:"foreignKey:DidID;references:ID"`
	Version             int
	VerificationMethods []SqlVerificationMethod `gorm:"foreignKey:DIDDocumentID;references:ID"`
	Services            []SqlService            `gorm:"foreignKey:DIDDocumentID;references:ID"`
}

func (d DIDDocument) TableName() string {
	return "did_document"
}

var _ DIDDocumentManager = (*SqlDIDDocumentManager)(nil)
var _ schema.Tabler = (*DID)(nil)

// DIDDocumentManager is the interface to change data for the did_document table
type DIDDocumentManager interface {
	// CreateOrUpdate adds a new version of a DID document, starts at 1
	CreateOrUpdate(did DID, verificationMethods []SqlVerificationMethod, services []SqlService) (*DIDDocument, error)
	// Latest returns the latest version of a DID document
	Latest(did did.DID) (*DIDDocument, error)
}

type SqlDIDDocumentManager struct {
	tx *gorm.DB
}

// NewDIDDocumentManager creates a new DIDDocumentManager for an open transaction
func NewDIDDocumentManager(tx *gorm.DB) *SqlDIDDocumentManager {
	return &SqlDIDDocumentManager{tx: tx}
}

func (s *SqlDIDDocumentManager) CreateOrUpdate(did DID, verificationMethods []SqlVerificationMethod, services []SqlService) (*DIDDocument, error) {
	latest := DIDDocument{}
	err := s.tx.Preload("DID").Where("did = ?", did.ID).Order("version desc").First(&latest).Error
	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, err
	}
	version := latest.Version + 1
	id := fmt.Sprintf("%s#%d", did.ID, version)
	// update DIDDocumentID for all VMs and services
	for i := range verificationMethods {
		verificationMethods[i].DIDDocumentID = id
	}
	for i := range services {
		services[i].DIDDocumentID = id
	}
	doc := DIDDocument{ID: id, DID: did, Version: version, VerificationMethods: verificationMethods, Services: services}
	err = s.tx.Create(&doc).Error
	return &doc, err
}

func (s *SqlDIDDocumentManager) Latest(did did.DID) (*DIDDocument, error) {
	doc := DIDDocument{}
	err := s.tx.Preload("DID").Preload("Services").Preload("VerificationMethods").Where("did = ?", did.String()).Order("version desc").First(&doc).Error
	if err != nil {
		return nil, err
	}
	return &doc, err
}

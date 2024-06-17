package sql

import "gorm.io/gorm/schema"

var _ schema.Tabler = (*SqlVerificationMethod)(nil)

type SqlVerificationMethod struct {
	ID            string `gorm:"primaryKey"`
	DIDDocumentID string `gorm:"column:did_document_id"`
	Data          []byte
}

func (v SqlVerificationMethod) TableName() string {
	return "did_verificationmethod"
}

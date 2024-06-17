package sql

import "gorm.io/gorm/schema"

var _ schema.Tabler = (*SqlService)(nil)

type SqlService struct {
	ID            string `gorm:"primaryKey"`
	DIDDocumentID string `gorm:"column:did_document_id"`
	Data          []byte
}

func (v SqlService) TableName() string {
	return "did_service"
}

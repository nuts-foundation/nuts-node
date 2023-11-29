package didweb

import (
	"encoding/json"
	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/did"
	"gorm.io/gorm"
	"gorm.io/gorm/schema"
)

type store interface {
	create(did string, methods ...did.VerificationMethod) error
	get(did string) ([]did.VerificationMethod, error)
}

var _ schema.Tabler = (*sqlDID)(nil)

type sqlDID struct {
	Did                 string                  `gorm:"primaryKey"`
	VerificationMethods []sqlVerificationMethod `gorm:"foreignKey:Did;references:Did"`
}

func (d sqlDID) TableName() string {
	return "vdr_didweb"
}

var _ schema.Tabler = (*sqlVerificationMethod)(nil)

type sqlVerificationMethod struct {
	ID         string `gorm:"primaryKey"`
	Did        string `gorm:"primaryKey"`
	MethodType string
	Data       string
}

func (v sqlVerificationMethod) TableName() string {
	return "vdr_didweb_verificationmethod"
}

var _ store = (*sqlStore)(nil)

type sqlStore struct {
	db *gorm.DB
}

func (s *sqlStore) create(did string, methods ...did.VerificationMethod) error {
	record := &sqlDID{Did: did}
	for _, method := range methods {
		data, _ := json.Marshal(method)
		record.VerificationMethods = append(record.VerificationMethods, sqlVerificationMethod{
			ID:         method.ID.String(),
			Did:        did,
			MethodType: string(method.Type),
			Data:       string(data),
		})
	}
	return s.db.Create(record).Error
}

func (s *sqlStore) get(id string) ([]did.VerificationMethod, error) {
	var verificationMethods []sqlVerificationMethod
	err := s.db.Model(&sqlDID{}).Where("did = ?", id).
		Association("VerificationMethods").
		Find(&verificationMethods)
	if err != nil {
		return nil, err
	}
	var result []did.VerificationMethod
	for _, curr := range verificationMethods {
		var method did.VerificationMethod
		if err := json.Unmarshal([]byte(curr.Data), &method); err != nil {
			return nil, err
		}
		result = append(result, method)
		vmID, err := did.ParseDIDURL(curr.ID)
		if err != nil {
			// weird
			return nil, err
		}
		method.ID = *vmID
		method.Type = ssi.KeyType(curr.MethodType)
	}
	return result, nil
}

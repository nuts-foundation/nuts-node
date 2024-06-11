package diddocument

import (
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/vdr/resolver"
	"gorm.io/gorm"
)

type SQLStore struct {
}

func (s *SQLStore) Get(tenantID string, id did.DID) ([]did.VerificationMethod, []did.Service, error) {
	var record sqlDID
	err := s.db.Model(&sqlDID{}).Where("did = ?", id.String()).
		Preload("VerificationMethods").
		Preload("Services").
		First(&record).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil, resolver.ErrNotFound
	}
	if err != nil {
		return nil, nil, err
	}

	var verificationMethods []did.VerificationMethod
	for _, curr := range record.VerificationMethods {
		var method did.VerificationMethod
		if err := json.Unmarshal(curr.Data, &method); err != nil {
			return nil, nil, err
		}
		verificationMethods = append(verificationMethods, method)
		vmID, err := did.ParseDIDURL(curr.ID)
		if err != nil {
			// weird
			return nil, nil, err
		}
		method.ID = *vmID
	}

	var services []did.Service
	for _, curr := range record.Services {
		var service did.Service
		if err := json.Unmarshal(curr.Data, &service); err != nil {
			return nil, nil, err
		}
		services = append(services, service)
	}

	return verificationMethods, services, nil
}

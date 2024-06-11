package diddocument

import (
	"encoding/json"
	"errors"
	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/vdr/resolver"
	"gorm.io/gorm"
	"gorm.io/gorm/schema"
)

type sqlTenant struct {
	ID                  string                  `gorm:"primaryKey"`
	VerificationMethods []sqlVerificationMethod `gorm:"foreignKey:TenantID;references:ID"`
	Services            []sqlService            `gorm:"foreignKey:TenantID;references:ID"`
}

var _ schema.Tabler = (*sqlVerificationMethod)(nil)

type sqlVerificationMethod struct {
	TenantID string `gorm:"primaryKey"`
	MethodID string `gorm:"primaryKey"`
	Data     []byte
}

func (v sqlVerificationMethod) TableName() string {
	return "tenant_verificationmethod"
}

var _ schema.Tabler = (*sqlService)(nil)

type sqlService struct {
	TenantID  string `gorm:"primaryKey"`
	ServiceID string `gorm:"primaryKey"`
	Data      []byte
}

func (v sqlService) TableName() string {
	return "tenant_service"
}

type SQLStore struct {
	DB *gorm.DB
}

// Get retrieves the DID document Verification Methods and Services for the given tenant.
// It constructs the IDs based on the given DID and the object's stored ID.
func (s *SQLStore) Get(tenantID string, id did.DID) ([]did.VerificationMethod, []did.Service, error) {
	var record sqlTenant
	err := s.DB.Model(&sqlTenant{}).Where("tenant_id = ?", tenantID).
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
		var vmID did.DIDURL
		vmID.DID = id
		vmID.Fragment = curr.MethodID
		method.ID = vmID
	}

	var services []did.Service
	for _, curr := range record.Services {
		var service did.Service
		if err := json.Unmarshal(curr.Data, &service); err != nil {
			return nil, nil, err
		}
		var serviceID did.DIDURL
		serviceID.DID = id
		serviceID.Fragment = curr.ServiceID
		service.ID = serviceID.URI()
		services = append(services, service)
	}

	return verificationMethods, services, nil
}

// createService creates a new service in the DID document identified by subjectDID.
// It does not validate the service.
func (s *sqlStore) createService(subjectDID did.DID, service did.Service) error {
	data, _ := json.Marshal(service)
	record := &sqlService{
		ID:   service.ID.String(),
		Did:  subjectDID.String(),
		Data: data,
	}
	err := s.db.Create(record).Error
	if errors.Is(err, gorm.ErrDuplicatedKey) {
		return errDuplicateService
	}
	if errors.Is(err, gorm.ErrForeignKeyViolated) {
		return errServiceDIDNotFound
	}
	return err
}

func (s *sqlStore) updateService(subjectDID did.DID, id ssi.URI, service did.Service) error {
	data, _ := json.Marshal(service)
	record := &sqlService{
		ID:   service.ID.String(),
		Did:  subjectDID.String(),
		Data: data,
	}
	result := s.db.Model(&sqlService{}).Where("did = ? AND id = ?", subjectDID.String(), id.String()).Updates(record)
	err := result.Error
	if errors.Is(err, gorm.ErrDuplicatedKey) {
		return errDuplicateService
	}
	if result.RowsAffected == 0 {
		return errServiceNotFound
	}
	return nil
}

func (s *sqlStore) deleteService(subjectDID did.DID, id ssi.URI) error {
	result := s.db.Model(&sqlService{}).Where("did = ? AND id = ?", subjectDID.String(), id.String()).Delete(&sqlService{})
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return errServiceNotFound
	}
	return nil
}

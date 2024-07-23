// Code generated by MockGen. DO NOT EDIT.
// Source: vdr/didsubject/management.go
//
// Generated by this command:
//
//	mockgen -destination=vdr/didsubject/management_mock.go -package=didsubject -source=vdr/didsubject/management.go
//

// Package didsubject is a generated GoMock package.
package didsubject

import (
	context "context"
	reflect "reflect"

	ssi "github.com/nuts-foundation/go-did"
	did "github.com/nuts-foundation/go-did/did"
	crypto "github.com/nuts-foundation/nuts-node/crypto"
	orm "github.com/nuts-foundation/nuts-node/storage/orm"
	gomock "go.uber.org/mock/gomock"
)

// MockMethodManager is a mock of MethodManager interface.
type MockMethodManager struct {
	ctrl     *gomock.Controller
	recorder *MockMethodManagerMockRecorder
}

// MockMethodManagerMockRecorder is the mock recorder for MockMethodManager.
type MockMethodManagerMockRecorder struct {
	mock *MockMethodManager
}

// NewMockMethodManager creates a new mock instance.
func NewMockMethodManager(ctrl *gomock.Controller) *MockMethodManager {
	mock := &MockMethodManager{ctrl: ctrl}
	mock.recorder = &MockMethodManagerMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockMethodManager) EXPECT() *MockMethodManagerMockRecorder {
	return m.recorder
}

// Commit mocks base method.
func (m *MockMethodManager) Commit(ctx context.Context, event orm.DIDChangeLog) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Commit", ctx, event)
	ret0, _ := ret[0].(error)
	return ret0
}

// Commit indicates an expected call of Commit.
func (mr *MockMethodManagerMockRecorder) Commit(ctx, event any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Commit", reflect.TypeOf((*MockMethodManager)(nil).Commit), ctx, event)
}

// IsCommitted mocks base method.
func (m *MockMethodManager) IsCommitted(ctx context.Context, event orm.DIDChangeLog) (bool, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "IsCommitted", ctx, event)
	ret0, _ := ret[0].(bool)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// IsCommitted indicates an expected call of IsCommitted.
func (mr *MockMethodManagerMockRecorder) IsCommitted(ctx, event any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "IsCommitted", reflect.TypeOf((*MockMethodManager)(nil).IsCommitted), ctx, event)
}

// NewDocument mocks base method.
func (m *MockMethodManager) NewDocument(ctx context.Context, keyFlags orm.DIDKeyFlags) (*orm.DIDDocument, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "NewDocument", ctx, keyFlags)
	ret0, _ := ret[0].(*orm.DIDDocument)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// NewDocument indicates an expected call of NewDocument.
func (mr *MockMethodManagerMockRecorder) NewDocument(ctx, keyFlags any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "NewDocument", reflect.TypeOf((*MockMethodManager)(nil).NewDocument), ctx, keyFlags)
}

// NewVerificationMethod mocks base method.
func (m *MockMethodManager) NewVerificationMethod(ctx context.Context, controller did.DID, keyUsage orm.DIDKeyFlags) (*did.VerificationMethod, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "NewVerificationMethod", ctx, controller, keyUsage)
	ret0, _ := ret[0].(*did.VerificationMethod)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// NewVerificationMethod indicates an expected call of NewVerificationMethod.
func (mr *MockMethodManagerMockRecorder) NewVerificationMethod(ctx, controller, keyUsage any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "NewVerificationMethod", reflect.TypeOf((*MockMethodManager)(nil).NewVerificationMethod), ctx, controller, keyUsage)
}

// MockDocumentManager is a mock of DocumentManager interface.
type MockDocumentManager struct {
	ctrl     *gomock.Controller
	recorder *MockDocumentManagerMockRecorder
}

// MockDocumentManagerMockRecorder is the mock recorder for MockDocumentManager.
type MockDocumentManagerMockRecorder struct {
	mock *MockDocumentManager
}

// NewMockDocumentManager creates a new mock instance.
func NewMockDocumentManager(ctrl *gomock.Controller) *MockDocumentManager {
	mock := &MockDocumentManager{ctrl: ctrl}
	mock.recorder = &MockDocumentManagerMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockDocumentManager) EXPECT() *MockDocumentManagerMockRecorder {
	return m.recorder
}

// AddVerificationMethod mocks base method.
func (m *MockDocumentManager) AddVerificationMethod(ctx context.Context, id did.DID, keyUsage orm.DIDKeyFlags) (*did.VerificationMethod, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "AddVerificationMethod", ctx, id, keyUsage)
	ret0, _ := ret[0].(*did.VerificationMethod)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// AddVerificationMethod indicates an expected call of AddVerificationMethod.
func (mr *MockDocumentManagerMockRecorder) AddVerificationMethod(ctx, id, keyUsage any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "AddVerificationMethod", reflect.TypeOf((*MockDocumentManager)(nil).AddVerificationMethod), ctx, id, keyUsage)
}

// Create mocks base method.
func (m *MockDocumentManager) Create(ctx context.Context, options CreationOptions) (*did.Document, crypto.Key, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Create", ctx, options)
	ret0, _ := ret[0].(*did.Document)
	ret1, _ := ret[1].(crypto.Key)
	ret2, _ := ret[2].(error)
	return ret0, ret1, ret2
}

// Create indicates an expected call of Create.
func (mr *MockDocumentManagerMockRecorder) Create(ctx, options any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Create", reflect.TypeOf((*MockDocumentManager)(nil).Create), ctx, options)
}

// Deactivate mocks base method.
func (m *MockDocumentManager) Deactivate(ctx context.Context, id did.DID) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Deactivate", ctx, id)
	ret0, _ := ret[0].(error)
	return ret0
}

// Deactivate indicates an expected call of Deactivate.
func (mr *MockDocumentManagerMockRecorder) Deactivate(ctx, id any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Deactivate", reflect.TypeOf((*MockDocumentManager)(nil).Deactivate), ctx, id)
}

// RemoveVerificationMethod mocks base method.
func (m *MockDocumentManager) RemoveVerificationMethod(ctx context.Context, id did.DID, keyID did.DIDURL) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "RemoveVerificationMethod", ctx, id, keyID)
	ret0, _ := ret[0].(error)
	return ret0
}

// RemoveVerificationMethod indicates an expected call of RemoveVerificationMethod.
func (mr *MockDocumentManagerMockRecorder) RemoveVerificationMethod(ctx, id, keyID any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "RemoveVerificationMethod", reflect.TypeOf((*MockDocumentManager)(nil).RemoveVerificationMethod), ctx, id, keyID)
}

// Update mocks base method.
func (m *MockDocumentManager) Update(ctx context.Context, id did.DID, next did.Document) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Update", ctx, id, next)
	ret0, _ := ret[0].(error)
	return ret0
}

// Update indicates an expected call of Update.
func (mr *MockDocumentManagerMockRecorder) Update(ctx, id, next any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Update", reflect.TypeOf((*MockDocumentManager)(nil).Update), ctx, id, next)
}

// MockSubjectManager is a mock of SubjectManager interface.
type MockSubjectManager struct {
	ctrl     *gomock.Controller
	recorder *MockSubjectManagerMockRecorder
}

// MockSubjectManagerMockRecorder is the mock recorder for MockSubjectManager.
type MockSubjectManagerMockRecorder struct {
	mock *MockSubjectManager
}

// NewMockSubjectManager creates a new mock instance.
func NewMockSubjectManager(ctrl *gomock.Controller) *MockSubjectManager {
	mock := &MockSubjectManager{ctrl: ctrl}
	mock.recorder = &MockSubjectManagerMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockSubjectManager) EXPECT() *MockSubjectManagerMockRecorder {
	return m.recorder
}

// AddVerificationMethod mocks base method.
func (m *MockSubjectManager) AddVerificationMethod(ctx context.Context, subject string, keyUsage orm.DIDKeyFlags) ([]did.VerificationMethod, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "AddVerificationMethod", ctx, subject, keyUsage)
	ret0, _ := ret[0].([]did.VerificationMethod)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// AddVerificationMethod indicates an expected call of AddVerificationMethod.
func (mr *MockSubjectManagerMockRecorder) AddVerificationMethod(ctx, subject, keyUsage any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "AddVerificationMethod", reflect.TypeOf((*MockSubjectManager)(nil).AddVerificationMethod), ctx, subject, keyUsage)
}

// Create mocks base method.
func (m *MockSubjectManager) Create(ctx context.Context, options CreationOptions) ([]did.Document, string, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Create", ctx, options)
	ret0, _ := ret[0].([]did.Document)
	ret1, _ := ret[1].(string)
	ret2, _ := ret[2].(error)
	return ret0, ret1, ret2
}

// Create indicates an expected call of Create.
func (mr *MockSubjectManagerMockRecorder) Create(ctx, options any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Create", reflect.TypeOf((*MockSubjectManager)(nil).Create), ctx, options)
}

// CreateService mocks base method.
func (m *MockSubjectManager) CreateService(ctx context.Context, subject string, service did.Service) ([]did.Service, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "CreateService", ctx, subject, service)
	ret0, _ := ret[0].([]did.Service)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// CreateService indicates an expected call of CreateService.
func (mr *MockSubjectManagerMockRecorder) CreateService(ctx, subject, service any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CreateService", reflect.TypeOf((*MockSubjectManager)(nil).CreateService), ctx, subject, service)
}

// Deactivate mocks base method.
func (m *MockSubjectManager) Deactivate(ctx context.Context, subject string) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Deactivate", ctx, subject)
	ret0, _ := ret[0].(error)
	return ret0
}

// Deactivate indicates an expected call of Deactivate.
func (mr *MockSubjectManagerMockRecorder) Deactivate(ctx, subject any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Deactivate", reflect.TypeOf((*MockSubjectManager)(nil).Deactivate), ctx, subject)
}

// DeleteService mocks base method.
func (m *MockSubjectManager) DeleteService(ctx context.Context, subject string, serviceID ssi.URI) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "DeleteService", ctx, subject, serviceID)
	ret0, _ := ret[0].(error)
	return ret0
}

// DeleteService indicates an expected call of DeleteService.
func (mr *MockSubjectManagerMockRecorder) DeleteService(ctx, subject, serviceID any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DeleteService", reflect.TypeOf((*MockSubjectManager)(nil).DeleteService), ctx, subject, serviceID)
}

// FindServices mocks base method.
func (m *MockSubjectManager) FindServices(ctx context.Context, subject string, serviceType *string) ([]did.Service, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "FindServices", ctx, subject, serviceType)
	ret0, _ := ret[0].([]did.Service)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// FindServices indicates an expected call of FindServices.
func (mr *MockSubjectManagerMockRecorder) FindServices(ctx, subject, serviceType any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "FindServices", reflect.TypeOf((*MockSubjectManager)(nil).FindServices), ctx, subject, serviceType)
}

// List mocks base method.
func (m *MockSubjectManager) List(ctx context.Context, subject string) ([]did.DID, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "List", ctx, subject)
	ret0, _ := ret[0].([]did.DID)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// List indicates an expected call of List.
func (mr *MockSubjectManagerMockRecorder) List(ctx, subject any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "List", reflect.TypeOf((*MockSubjectManager)(nil).List), ctx, subject)
}

// UpdateService mocks base method.
func (m *MockSubjectManager) UpdateService(ctx context.Context, subject string, serviceID ssi.URI, service did.Service) ([]did.Service, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "UpdateService", ctx, subject, serviceID, service)
	ret0, _ := ret[0].([]did.Service)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// UpdateService indicates an expected call of UpdateService.
func (mr *MockSubjectManagerMockRecorder) UpdateService(ctx, subject, serviceID, service any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "UpdateService", reflect.TypeOf((*MockSubjectManager)(nil).UpdateService), ctx, subject, serviceID, service)
}

// MockCreationOptions is a mock of CreationOptions interface.
type MockCreationOptions struct {
	ctrl     *gomock.Controller
	recorder *MockCreationOptionsMockRecorder
}

// MockCreationOptionsMockRecorder is the mock recorder for MockCreationOptions.
type MockCreationOptionsMockRecorder struct {
	mock *MockCreationOptions
}

// NewMockCreationOptions creates a new mock instance.
func NewMockCreationOptions(ctrl *gomock.Controller) *MockCreationOptions {
	mock := &MockCreationOptions{ctrl: ctrl}
	mock.recorder = &MockCreationOptionsMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockCreationOptions) EXPECT() *MockCreationOptionsMockRecorder {
	return m.recorder
}

// All mocks base method.
func (m *MockCreationOptions) All() []CreationOption {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "All")
	ret0, _ := ret[0].([]CreationOption)
	return ret0
}

// All indicates an expected call of All.
func (mr *MockCreationOptionsMockRecorder) All() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "All", reflect.TypeOf((*MockCreationOptions)(nil).All))
}

// With mocks base method.
func (m *MockCreationOptions) With(option CreationOption) CreationOptions {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "With", option)
	ret0, _ := ret[0].(CreationOptions)
	return ret0
}

// With indicates an expected call of With.
func (mr *MockCreationOptionsMockRecorder) With(option any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "With", reflect.TypeOf((*MockCreationOptions)(nil).With), option)
}

// MockCreationOption is a mock of CreationOption interface.
type MockCreationOption struct {
	ctrl     *gomock.Controller
	recorder *MockCreationOptionMockRecorder
}

// MockCreationOptionMockRecorder is the mock recorder for MockCreationOption.
type MockCreationOptionMockRecorder struct {
	mock *MockCreationOption
}

// NewMockCreationOption creates a new mock instance.
func NewMockCreationOption(ctrl *gomock.Controller) *MockCreationOption {
	mock := &MockCreationOption{ctrl: ctrl}
	mock.recorder = &MockCreationOptionMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockCreationOption) EXPECT() *MockCreationOptionMockRecorder {
	return m.recorder
}

// MockDocumentOwner is a mock of DocumentOwner interface.
type MockDocumentOwner struct {
	ctrl     *gomock.Controller
	recorder *MockDocumentOwnerMockRecorder
}

// MockDocumentOwnerMockRecorder is the mock recorder for MockDocumentOwner.
type MockDocumentOwnerMockRecorder struct {
	mock *MockDocumentOwner
}

// NewMockDocumentOwner creates a new mock instance.
func NewMockDocumentOwner(ctrl *gomock.Controller) *MockDocumentOwner {
	mock := &MockDocumentOwner{ctrl: ctrl}
	mock.recorder = &MockDocumentOwnerMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockDocumentOwner) EXPECT() *MockDocumentOwnerMockRecorder {
	return m.recorder
}

// IsOwner mocks base method.
func (m *MockDocumentOwner) IsOwner(arg0 context.Context, arg1 did.DID) (bool, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "IsOwner", arg0, arg1)
	ret0, _ := ret[0].(bool)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// IsOwner indicates an expected call of IsOwner.
func (mr *MockDocumentOwnerMockRecorder) IsOwner(arg0, arg1 any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "IsOwner", reflect.TypeOf((*MockDocumentOwner)(nil).IsOwner), arg0, arg1)
}

// ListOwned mocks base method.
func (m *MockDocumentOwner) ListOwned(ctx context.Context) ([]did.DID, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ListOwned", ctx)
	ret0, _ := ret[0].([]did.DID)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// ListOwned indicates an expected call of ListOwned.
func (mr *MockDocumentOwnerMockRecorder) ListOwned(ctx any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ListOwned", reflect.TypeOf((*MockDocumentOwner)(nil).ListOwned), ctx)
}

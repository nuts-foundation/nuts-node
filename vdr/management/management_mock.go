// Code generated by MockGen. DO NOT EDIT.
// Source: vdr/management/management.go
//
// Generated by this command:
//
//	mockgen -destination=vdr/management/management_mock.go -package=management -source=vdr/management/management.go
//
// Package management is a generated GoMock package.
package management

import (
	context "context"
	reflect "reflect"

	did "github.com/nuts-foundation/go-did/did"
	crypto "github.com/nuts-foundation/nuts-node/crypto"
	gomock "go.uber.org/mock/gomock"
)

// MockDocCreator is a mock of DocCreator interface.
type MockDocCreator struct {
	ctrl     *gomock.Controller
	recorder *MockDocCreatorMockRecorder
}

// MockDocCreatorMockRecorder is the mock recorder for MockDocCreator.
type MockDocCreatorMockRecorder struct {
	mock *MockDocCreator
}

// NewMockDocCreator creates a new mock instance.
func NewMockDocCreator(ctrl *gomock.Controller) *MockDocCreator {
	mock := &MockDocCreator{ctrl: ctrl}
	mock.recorder = &MockDocCreatorMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockDocCreator) EXPECT() *MockDocCreatorMockRecorder {
	return m.recorder
}

// Create mocks base method.
func (m *MockDocCreator) Create(ctx context.Context, options DIDCreationOptions) (*did.Document, crypto.Key, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Create", ctx, options)
	ret0, _ := ret[0].(*did.Document)
	ret1, _ := ret[1].(crypto.Key)
	ret2, _ := ret[2].(error)
	return ret0, ret1, ret2
}

// Create indicates an expected call of Create.
func (mr *MockDocCreatorMockRecorder) Create(ctx, options any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Create", reflect.TypeOf((*MockDocCreator)(nil).Create), ctx, options)
}

// MockDocUpdater is a mock of DocUpdater interface.
type MockDocUpdater struct {
	ctrl     *gomock.Controller
	recorder *MockDocUpdaterMockRecorder
}

// MockDocUpdaterMockRecorder is the mock recorder for MockDocUpdater.
type MockDocUpdaterMockRecorder struct {
	mock *MockDocUpdater
}

// NewMockDocUpdater creates a new mock instance.
func NewMockDocUpdater(ctrl *gomock.Controller) *MockDocUpdater {
	mock := &MockDocUpdater{ctrl: ctrl}
	mock.recorder = &MockDocUpdaterMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockDocUpdater) EXPECT() *MockDocUpdaterMockRecorder {
	return m.recorder
}

// Update mocks base method.
func (m *MockDocUpdater) Update(ctx context.Context, id did.DID, next did.Document) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Update", ctx, id, next)
	ret0, _ := ret[0].(error)
	return ret0
}

// Update indicates an expected call of Update.
func (mr *MockDocUpdaterMockRecorder) Update(ctx, id, next any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Update", reflect.TypeOf((*MockDocUpdater)(nil).Update), ctx, id, next)
}

// MockDocManipulator is a mock of DocManipulator interface.
type MockDocManipulator struct {
	ctrl     *gomock.Controller
	recorder *MockDocManipulatorMockRecorder
}

// MockDocManipulatorMockRecorder is the mock recorder for MockDocManipulator.
type MockDocManipulatorMockRecorder struct {
	mock *MockDocManipulator
}

// NewMockDocManipulator creates a new mock instance.
func NewMockDocManipulator(ctrl *gomock.Controller) *MockDocManipulator {
	mock := &MockDocManipulator{ctrl: ctrl}
	mock.recorder = &MockDocManipulatorMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockDocManipulator) EXPECT() *MockDocManipulatorMockRecorder {
	return m.recorder
}

// AddVerificationMethod mocks base method.
func (m *MockDocManipulator) AddVerificationMethod(ctx context.Context, id did.DID, keyUsage DIDKeyFlags) (*did.VerificationMethod, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "AddVerificationMethod", ctx, id, keyUsage)
	ret0, _ := ret[0].(*did.VerificationMethod)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// AddVerificationMethod indicates an expected call of AddVerificationMethod.
func (mr *MockDocManipulatorMockRecorder) AddVerificationMethod(ctx, id, keyUsage any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "AddVerificationMethod", reflect.TypeOf((*MockDocManipulator)(nil).AddVerificationMethod), ctx, id, keyUsage)
}

// Deactivate mocks base method.
func (m *MockDocManipulator) Deactivate(ctx context.Context, id did.DID) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Deactivate", ctx, id)
	ret0, _ := ret[0].(error)
	return ret0
}

// Deactivate indicates an expected call of Deactivate.
func (mr *MockDocManipulatorMockRecorder) Deactivate(ctx, id any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Deactivate", reflect.TypeOf((*MockDocManipulator)(nil).Deactivate), ctx, id)
}

// RemoveVerificationMethod mocks base method.
func (m *MockDocManipulator) RemoveVerificationMethod(ctx context.Context, id, keyID did.DID) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "RemoveVerificationMethod", ctx, id, keyID)
	ret0, _ := ret[0].(error)
	return ret0
}

// RemoveVerificationMethod indicates an expected call of RemoveVerificationMethod.
func (mr *MockDocManipulatorMockRecorder) RemoveVerificationMethod(ctx, id, keyID any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "RemoveVerificationMethod", reflect.TypeOf((*MockDocManipulator)(nil).RemoveVerificationMethod), ctx, id, keyID)
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
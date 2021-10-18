// Code generated by MockGen. DO NOT EDIT.
// Source: vdr/types/interface.go

// Package types is a generated GoMock package.
package types

import (
	crypto "crypto"
	reflect "reflect"
	time "time"

	gomock "github.com/golang/mock/gomock"
	go_did "github.com/nuts-foundation/go-did"
	did "github.com/nuts-foundation/go-did/did"
	crypto0 "github.com/nuts-foundation/nuts-node/crypto"
	hash "github.com/nuts-foundation/nuts-node/crypto/hash"
)

// MockDocResolver is a mock of DocResolver interface.
type MockDocResolver struct {
	ctrl     *gomock.Controller
	recorder *MockDocResolverMockRecorder
}

// MockDocResolverMockRecorder is the mock recorder for MockDocResolver.
type MockDocResolverMockRecorder struct {
	mock *MockDocResolver
}

// NewMockDocResolver creates a new mock instance.
func NewMockDocResolver(ctrl *gomock.Controller) *MockDocResolver {
	mock := &MockDocResolver{ctrl: ctrl}
	mock.recorder = &MockDocResolverMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockDocResolver) EXPECT() *MockDocResolverMockRecorder {
	return m.recorder
}

// Resolve mocks base method.
func (m *MockDocResolver) Resolve(id did.DID, metadata *ResolveMetadata) (*did.Document, *DocumentMetadata, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Resolve", id, metadata)
	ret0, _ := ret[0].(*did.Document)
	ret1, _ := ret[1].(*DocumentMetadata)
	ret2, _ := ret[2].(error)
	return ret0, ret1, ret2
}

// Resolve indicates an expected call of Resolve.
func (mr *MockDocResolverMockRecorder) Resolve(id, metadata interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Resolve", reflect.TypeOf((*MockDocResolver)(nil).Resolve), id, metadata)
}

// ResolveControllers mocks base method.
func (m *MockDocResolver) ResolveControllers(input did.Document, metadata *ResolveMetadata) ([]did.Document, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ResolveControllers", input, metadata)
	ret0, _ := ret[0].([]did.Document)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// ResolveControllers indicates an expected call of ResolveControllers.
func (mr *MockDocResolverMockRecorder) ResolveControllers(input, metadata interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ResolveControllers", reflect.TypeOf((*MockDocResolver)(nil).ResolveControllers), input, metadata)
}

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
func (m *MockDocCreator) Create(options DIDCreationOptions) (*did.Document, crypto0.Key, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Create", options)
	ret0, _ := ret[0].(*did.Document)
	ret1, _ := ret[1].(crypto0.Key)
	ret2, _ := ret[2].(error)
	return ret0, ret1, ret2
}

// Create indicates an expected call of Create.
func (mr *MockDocCreatorMockRecorder) Create(options interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Create", reflect.TypeOf((*MockDocCreator)(nil).Create), options)
}

// MockDocWriter is a mock of DocWriter interface.
type MockDocWriter struct {
	ctrl     *gomock.Controller
	recorder *MockDocWriterMockRecorder
}

// MockDocWriterMockRecorder is the mock recorder for MockDocWriter.
type MockDocWriterMockRecorder struct {
	mock *MockDocWriter
}

// NewMockDocWriter creates a new mock instance.
func NewMockDocWriter(ctrl *gomock.Controller) *MockDocWriter {
	mock := &MockDocWriter{ctrl: ctrl}
	mock.recorder = &MockDocWriterMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockDocWriter) EXPECT() *MockDocWriterMockRecorder {
	return m.recorder
}

// Write mocks base method.
func (m *MockDocWriter) Write(document did.Document, metadata DocumentMetadata) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Write", document, metadata)
	ret0, _ := ret[0].(error)
	return ret0
}

// Write indicates an expected call of Write.
func (mr *MockDocWriterMockRecorder) Write(document, metadata interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Write", reflect.TypeOf((*MockDocWriter)(nil).Write), document, metadata)
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
func (m *MockDocUpdater) Update(id did.DID, current hash.SHA256Hash, next did.Document, metadata *DocumentMetadata) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Update", id, current, next, metadata)
	ret0, _ := ret[0].(error)
	return ret0
}

// Update indicates an expected call of Update.
func (mr *MockDocUpdaterMockRecorder) Update(id, current, next, metadata interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Update", reflect.TypeOf((*MockDocUpdater)(nil).Update), id, current, next, metadata)
}

// MockKeyResolver is a mock of KeyResolver interface.
type MockKeyResolver struct {
	ctrl     *gomock.Controller
	recorder *MockKeyResolverMockRecorder
}

// MockKeyResolverMockRecorder is the mock recorder for MockKeyResolver.
type MockKeyResolverMockRecorder struct {
	mock *MockKeyResolver
}

// NewMockKeyResolver creates a new mock instance.
func NewMockKeyResolver(ctrl *gomock.Controller) *MockKeyResolver {
	mock := &MockKeyResolver{ctrl: ctrl}
	mock.recorder = &MockKeyResolverMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockKeyResolver) EXPECT() *MockKeyResolverMockRecorder {
	return m.recorder
}

// ResolveAssertionKeyID mocks base method.
func (m *MockKeyResolver) ResolveAssertionKeyID(id did.DID) (go_did.URI, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ResolveAssertionKeyID", id)
	ret0, _ := ret[0].(go_did.URI)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// ResolveAssertionKeyID indicates an expected call of ResolveAssertionKeyID.
func (mr *MockKeyResolverMockRecorder) ResolveAssertionKeyID(id interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ResolveAssertionKeyID", reflect.TypeOf((*MockKeyResolver)(nil).ResolveAssertionKeyID), id)
}

// ResolvePublicKey mocks base method.
func (m *MockKeyResolver) ResolvePublicKey(kid string, sourceTransactionsRefs []hash.SHA256Hash) (crypto.PublicKey, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ResolvePublicKey", kid, sourceTransactionsRefs)
	ret0, _ := ret[0].(crypto.PublicKey)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// ResolvePublicKey indicates an expected call of ResolvePublicKey.
func (mr *MockKeyResolverMockRecorder) ResolvePublicKey(kid, sourceTransactionsRefs interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ResolvePublicKey", reflect.TypeOf((*MockKeyResolver)(nil).ResolvePublicKey), kid, sourceTransactionsRefs)
}

// ResolvePublicKeyInTime mocks base method.
func (m *MockKeyResolver) ResolvePublicKeyInTime(kid string, validAt *time.Time) (crypto.PublicKey, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ResolvePublicKeyInTime", kid, validAt)
	ret0, _ := ret[0].(crypto.PublicKey)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// ResolvePublicKeyInTime indicates an expected call of ResolvePublicKeyInTime.
func (mr *MockKeyResolverMockRecorder) ResolvePublicKeyInTime(kid, validAt interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ResolvePublicKeyInTime", reflect.TypeOf((*MockKeyResolver)(nil).ResolvePublicKeyInTime), kid, validAt)
}

// ResolveSigningKey mocks base method.
func (m *MockKeyResolver) ResolveSigningKey(keyID string, validAt *time.Time) (crypto.PublicKey, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ResolveSigningKey", keyID, validAt)
	ret0, _ := ret[0].(crypto.PublicKey)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// ResolveSigningKey indicates an expected call of ResolveSigningKey.
func (mr *MockKeyResolverMockRecorder) ResolveSigningKey(keyID, validAt interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ResolveSigningKey", reflect.TypeOf((*MockKeyResolver)(nil).ResolveSigningKey), keyID, validAt)
}

// ResolveSigningKeyID mocks base method.
func (m *MockKeyResolver) ResolveSigningKeyID(holder did.DID, validAt *time.Time) (string, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ResolveSigningKeyID", holder, validAt)
	ret0, _ := ret[0].(string)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// ResolveSigningKeyID indicates an expected call of ResolveSigningKeyID.
func (mr *MockKeyResolverMockRecorder) ResolveSigningKeyID(holder, validAt interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ResolveSigningKeyID", reflect.TypeOf((*MockKeyResolver)(nil).ResolveSigningKeyID), holder, validAt)
}

// MockStore is a mock of Store interface.
type MockStore struct {
	ctrl     *gomock.Controller
	recorder *MockStoreMockRecorder
}

// MockStoreMockRecorder is the mock recorder for MockStore.
type MockStoreMockRecorder struct {
	mock *MockStore
}

// NewMockStore creates a new mock instance.
func NewMockStore(ctrl *gomock.Controller) *MockStore {
	mock := &MockStore{ctrl: ctrl}
	mock.recorder = &MockStoreMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockStore) EXPECT() *MockStoreMockRecorder {
	return m.recorder
}

// Iterate mocks base method.
func (m *MockStore) Iterate(fn DocIterator) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Iterate", fn)
	ret0, _ := ret[0].(error)
	return ret0
}

// Iterate indicates an expected call of Iterate.
func (mr *MockStoreMockRecorder) Iterate(fn interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Iterate", reflect.TypeOf((*MockStore)(nil).Iterate), fn)
}

// Resolve mocks base method.
func (m *MockStore) Resolve(id did.DID, metadata *ResolveMetadata) (*did.Document, *DocumentMetadata, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Resolve", id, metadata)
	ret0, _ := ret[0].(*did.Document)
	ret1, _ := ret[1].(*DocumentMetadata)
	ret2, _ := ret[2].(error)
	return ret0, ret1, ret2
}

// Resolve indicates an expected call of Resolve.
func (mr *MockStoreMockRecorder) Resolve(id, metadata interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Resolve", reflect.TypeOf((*MockStore)(nil).Resolve), id, metadata)
}

// Update mocks base method.
func (m *MockStore) Update(id did.DID, current hash.SHA256Hash, next did.Document, metadata *DocumentMetadata) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Update", id, current, next, metadata)
	ret0, _ := ret[0].(error)
	return ret0
}

// Update indicates an expected call of Update.
func (mr *MockStoreMockRecorder) Update(id, current, next, metadata interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Update", reflect.TypeOf((*MockStore)(nil).Update), id, current, next, metadata)
}

// Write mocks base method.
func (m *MockStore) Write(document did.Document, metadata DocumentMetadata) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Write", document, metadata)
	ret0, _ := ret[0].(error)
	return ret0
}

// Write indicates an expected call of Write.
func (mr *MockStoreMockRecorder) Write(document, metadata interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Write", reflect.TypeOf((*MockStore)(nil).Write), document, metadata)
}

// MockVDR is a mock of VDR interface.
type MockVDR struct {
	ctrl     *gomock.Controller
	recorder *MockVDRMockRecorder
}

// MockVDRMockRecorder is the mock recorder for MockVDR.
type MockVDRMockRecorder struct {
	mock *MockVDR
}

// NewMockVDR creates a new mock instance.
func NewMockVDR(ctrl *gomock.Controller) *MockVDR {
	mock := &MockVDR{ctrl: ctrl}
	mock.recorder = &MockVDRMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockVDR) EXPECT() *MockVDRMockRecorder {
	return m.recorder
}

// ConflictedDocuments mocks base method.
func (m *MockVDR) ConflictedDocuments() ([]did.Document, []DocumentMetadata, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ConflictedDocuments")
	ret0, _ := ret[0].([]did.Document)
	ret1, _ := ret[1].([]DocumentMetadata)
	ret2, _ := ret[2].(error)
	return ret0, ret1, ret2
}

// ConflictedDocuments indicates an expected call of ConflictedDocuments.
func (mr *MockVDRMockRecorder) ConflictedDocuments() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ConflictedDocuments", reflect.TypeOf((*MockVDR)(nil).ConflictedDocuments))
}

// Create mocks base method.
func (m *MockVDR) Create(options DIDCreationOptions) (*did.Document, crypto0.Key, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Create", options)
	ret0, _ := ret[0].(*did.Document)
	ret1, _ := ret[1].(crypto0.Key)
	ret2, _ := ret[2].(error)
	return ret0, ret1, ret2
}

// Create indicates an expected call of Create.
func (mr *MockVDRMockRecorder) Create(options interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Create", reflect.TypeOf((*MockVDR)(nil).Create), options)
}

// Update mocks base method.
func (m *MockVDR) Update(id did.DID, current hash.SHA256Hash, next did.Document, metadata *DocumentMetadata) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Update", id, current, next, metadata)
	ret0, _ := ret[0].(error)
	return ret0
}

// Update indicates an expected call of Update.
func (mr *MockVDRMockRecorder) Update(id, current, next, metadata interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Update", reflect.TypeOf((*MockVDR)(nil).Update), id, current, next, metadata)
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
func (m *MockDocManipulator) AddVerificationMethod(id did.DID) (*did.VerificationMethod, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "AddVerificationMethod", id)
	ret0, _ := ret[0].(*did.VerificationMethod)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// AddVerificationMethod indicates an expected call of AddVerificationMethod.
func (mr *MockDocManipulatorMockRecorder) AddVerificationMethod(id interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "AddVerificationMethod", reflect.TypeOf((*MockDocManipulator)(nil).AddVerificationMethod), id)
}

// Deactivate mocks base method.
func (m *MockDocManipulator) Deactivate(id did.DID) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Deactivate", id)
	ret0, _ := ret[0].(error)
	return ret0
}

// Deactivate indicates an expected call of Deactivate.
func (mr *MockDocManipulatorMockRecorder) Deactivate(id interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Deactivate", reflect.TypeOf((*MockDocManipulator)(nil).Deactivate), id)
}

// RemoveVerificationMethod mocks base method.
func (m *MockDocManipulator) RemoveVerificationMethod(id, keyID did.DID) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "RemoveVerificationMethod", id, keyID)
	ret0, _ := ret[0].(error)
	return ret0
}

// RemoveVerificationMethod indicates an expected call of RemoveVerificationMethod.
func (mr *MockDocManipulatorMockRecorder) RemoveVerificationMethod(id, keyID interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "RemoveVerificationMethod", reflect.TypeOf((*MockDocManipulator)(nil).RemoveVerificationMethod), id, keyID)
}

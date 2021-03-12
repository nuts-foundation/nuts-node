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
func (m *MockDocResolver) Resolve(id go_did.DID, metadata *ResolveMetadata) (*go_did.Document, *DocumentMetadata, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Resolve", id, metadata)
	ret0, _ := ret[0].(*go_did.Document)
	ret1, _ := ret[1].(*DocumentMetadata)
	ret2, _ := ret[2].(error)
	return ret0, ret1, ret2
}

// Resolve indicates an expected call of Resolve.
func (mr *MockDocResolverMockRecorder) Resolve(id, metadata interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Resolve", reflect.TypeOf((*MockDocResolver)(nil).Resolve), id, metadata)
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
func (m *MockDocCreator) Create() (*go_did.Document, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Create")
	ret0, _ := ret[0].(*go_did.Document)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Create indicates an expected call of Create.
func (mr *MockDocCreatorMockRecorder) Create() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Create", reflect.TypeOf((*MockDocCreator)(nil).Create))
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
func (m *MockDocWriter) Write(document go_did.Document, metadata DocumentMetadata) error {
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
func (m *MockDocUpdater) Update(id go_did.DID, current hash.SHA256Hash, next go_did.Document, metadata *DocumentMetadata) error {
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

// MockDocDeactivator is a mock of DocDeactivator interface.
type MockDocDeactivator struct {
	ctrl     *gomock.Controller
	recorder *MockDocDeactivatorMockRecorder
}

// MockDocDeactivatorMockRecorder is the mock recorder for MockDocDeactivator.
type MockDocDeactivatorMockRecorder struct {
	mock *MockDocDeactivator
}

// NewMockDocDeactivator creates a new mock instance.
func NewMockDocDeactivator(ctrl *gomock.Controller) *MockDocDeactivator {
	mock := &MockDocDeactivator{ctrl: ctrl}
	mock.recorder = &MockDocDeactivatorMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockDocDeactivator) EXPECT() *MockDocDeactivatorMockRecorder {
	return m.recorder
}

// Deactivate mocks base method.
func (m *MockDocDeactivator) Deactivate(id go_did.DID, current hash.SHA256Hash) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Deactivate", id, current)
	ret0, _ := ret[0].(error)
	return ret0
}

// Deactivate indicates an expected call of Deactivate.
func (mr *MockDocDeactivatorMockRecorder) Deactivate(id, current interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Deactivate", reflect.TypeOf((*MockDocDeactivator)(nil).Deactivate), id, current)
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

// ResolveAssertionKey mocks base method.
func (m *MockKeyResolver) ResolveAssertionKey(id go_did.DID) (go_did.URI, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ResolveAssertionKey", id)
	ret0, _ := ret[0].(go_did.URI)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// ResolveAssertionKey indicates an expected call of ResolveAssertionKey.
func (mr *MockKeyResolverMockRecorder) ResolveAssertionKey(id interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ResolveAssertionKey", reflect.TypeOf((*MockKeyResolver)(nil).ResolveAssertionKey), id)
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
func (m *MockKeyResolver) ResolveSigningKeyID(holder go_did.DID, validAt *time.Time) (string, error) {
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

// Resolve mocks base method.
func (m *MockStore) Resolve(id go_did.DID, metadata *ResolveMetadata) (*go_did.Document, *DocumentMetadata, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Resolve", id, metadata)
	ret0, _ := ret[0].(*go_did.Document)
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
func (m *MockStore) Update(id go_did.DID, current hash.SHA256Hash, next go_did.Document, metadata *DocumentMetadata) error {
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
func (m *MockStore) Write(document go_did.Document, metadata DocumentMetadata) error {
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

// Create mocks base method.
func (m *MockVDR) Create() (*go_did.Document, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Create")
	ret0, _ := ret[0].(*go_did.Document)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Create indicates an expected call of Create.
func (mr *MockVDRMockRecorder) Create() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Create", reflect.TypeOf((*MockVDR)(nil).Create))
}

// Deactivate mocks base method.
func (m *MockVDR) Deactivate(id go_did.DID, current hash.SHA256Hash) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Deactivate", id, current)
	ret0, _ := ret[0].(error)
	return ret0
}

// Deactivate indicates an expected call of Deactivate.
func (mr *MockVDRMockRecorder) Deactivate(id, current interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Deactivate", reflect.TypeOf((*MockVDR)(nil).Deactivate), id, current)
}

// Resolve mocks base method.
func (m *MockVDR) Resolve(id go_did.DID, metadata *ResolveMetadata) (*go_did.Document, *DocumentMetadata, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Resolve", id, metadata)
	ret0, _ := ret[0].(*go_did.Document)
	ret1, _ := ret[1].(*DocumentMetadata)
	ret2, _ := ret[2].(error)
	return ret0, ret1, ret2
}

// Resolve indicates an expected call of Resolve.
func (mr *MockVDRMockRecorder) Resolve(id, metadata interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Resolve", reflect.TypeOf((*MockVDR)(nil).Resolve), id, metadata)
}

// ResolveAssertionKey mocks base method.
func (m *MockVDR) ResolveAssertionKey(id go_did.DID) (go_did.URI, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ResolveAssertionKey", id)
	ret0, _ := ret[0].(go_did.URI)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// ResolveAssertionKey indicates an expected call of ResolveAssertionKey.
func (mr *MockVDRMockRecorder) ResolveAssertionKey(id interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ResolveAssertionKey", reflect.TypeOf((*MockVDR)(nil).ResolveAssertionKey), id)
}

// ResolveSigningKey mocks base method.
func (m *MockVDR) ResolveSigningKey(keyID string, validAt *time.Time) (crypto.PublicKey, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ResolveSigningKey", keyID, validAt)
	ret0, _ := ret[0].(crypto.PublicKey)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// ResolveSigningKey indicates an expected call of ResolveSigningKey.
func (mr *MockVDRMockRecorder) ResolveSigningKey(keyID, validAt interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ResolveSigningKey", reflect.TypeOf((*MockVDR)(nil).ResolveSigningKey), keyID, validAt)
}

// ResolveSigningKeyID mocks base method.
func (m *MockVDR) ResolveSigningKeyID(holder go_did.DID, validAt *time.Time) (string, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ResolveSigningKeyID", holder, validAt)
	ret0, _ := ret[0].(string)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// ResolveSigningKeyID indicates an expected call of ResolveSigningKeyID.
func (mr *MockVDRMockRecorder) ResolveSigningKeyID(holder, validAt interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ResolveSigningKeyID", reflect.TypeOf((*MockVDR)(nil).ResolveSigningKeyID), holder, validAt)
}

// Update mocks base method.
func (m *MockVDR) Update(id go_did.DID, current hash.SHA256Hash, next go_did.Document, metadata *DocumentMetadata) error {
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

// MockResolver is a mock of Resolver interface.
type MockResolver struct {
	ctrl     *gomock.Controller
	recorder *MockResolverMockRecorder
}

// MockResolverMockRecorder is the mock recorder for MockResolver.
type MockResolverMockRecorder struct {
	mock *MockResolver
}

// NewMockResolver creates a new mock instance.
func NewMockResolver(ctrl *gomock.Controller) *MockResolver {
	mock := &MockResolver{ctrl: ctrl}
	mock.recorder = &MockResolverMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockResolver) EXPECT() *MockResolverMockRecorder {
	return m.recorder
}

// Resolve mocks base method.
func (m *MockResolver) Resolve(id go_did.DID, metadata *ResolveMetadata) (*go_did.Document, *DocumentMetadata, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Resolve", id, metadata)
	ret0, _ := ret[0].(*go_did.Document)
	ret1, _ := ret[1].(*DocumentMetadata)
	ret2, _ := ret[2].(error)
	return ret0, ret1, ret2
}

// Resolve indicates an expected call of Resolve.
func (mr *MockResolverMockRecorder) Resolve(id, metadata interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Resolve", reflect.TypeOf((*MockResolver)(nil).Resolve), id, metadata)
}

// ResolveAssertionKey mocks base method.
func (m *MockResolver) ResolveAssertionKey(id go_did.DID) (go_did.URI, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ResolveAssertionKey", id)
	ret0, _ := ret[0].(go_did.URI)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// ResolveAssertionKey indicates an expected call of ResolveAssertionKey.
func (mr *MockResolverMockRecorder) ResolveAssertionKey(id interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ResolveAssertionKey", reflect.TypeOf((*MockResolver)(nil).ResolveAssertionKey), id)
}

// ResolveSigningKey mocks base method.
func (m *MockResolver) ResolveSigningKey(keyID string, validAt *time.Time) (crypto.PublicKey, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ResolveSigningKey", keyID, validAt)
	ret0, _ := ret[0].(crypto.PublicKey)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// ResolveSigningKey indicates an expected call of ResolveSigningKey.
func (mr *MockResolverMockRecorder) ResolveSigningKey(keyID, validAt interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ResolveSigningKey", reflect.TypeOf((*MockResolver)(nil).ResolveSigningKey), keyID, validAt)
}

// ResolveSigningKeyID mocks base method.
func (m *MockResolver) ResolveSigningKeyID(holder go_did.DID, validAt *time.Time) (string, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ResolveSigningKeyID", holder, validAt)
	ret0, _ := ret[0].(string)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// ResolveSigningKeyID indicates an expected call of ResolveSigningKeyID.
func (mr *MockResolverMockRecorder) ResolveSigningKeyID(holder, validAt interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ResolveSigningKeyID", reflect.TypeOf((*MockResolver)(nil).ResolveSigningKeyID), holder, validAt)
}

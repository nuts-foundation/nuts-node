// Code generated by MockGen. DO NOT EDIT.
// Source: vcr/issuer/interface.go

// Package issuer is a generated GoMock package.
package issuer

import (
	reflect "reflect"
	time "time"

	gomock "github.com/golang/mock/gomock"
	go_did "github.com/nuts-foundation/go-did"
	did "github.com/nuts-foundation/go-did/did"
	vc "github.com/nuts-foundation/go-did/vc"
	crypto "github.com/nuts-foundation/nuts-node/crypto"
	credential "github.com/nuts-foundation/nuts-node/vcr/credential"
)

// MockPublisher is a mock of Publisher interface.
type MockPublisher struct {
	ctrl     *gomock.Controller
	recorder *MockPublisherMockRecorder
}

// MockPublisherMockRecorder is the mock recorder for MockPublisher.
type MockPublisherMockRecorder struct {
	mock *MockPublisher
}

// NewMockPublisher creates a new mock instance.
func NewMockPublisher(ctrl *gomock.Controller) *MockPublisher {
	mock := &MockPublisher{ctrl: ctrl}
	mock.recorder = &MockPublisherMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockPublisher) EXPECT() *MockPublisherMockRecorder {
	return m.recorder
}

// PublishCredential mocks base method.
func (m *MockPublisher) PublishCredential(verifiableCredential vc.VerifiableCredential, public bool) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "PublishCredential", verifiableCredential, public)
	ret0, _ := ret[0].(error)
	return ret0
}

// PublishCredential indicates an expected call of PublishCredential.
func (mr *MockPublisherMockRecorder) PublishCredential(verifiableCredential, public interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "PublishCredential", reflect.TypeOf((*MockPublisher)(nil).PublishCredential), verifiableCredential, public)
}

// PublishRevocation mocks base method.
func (m *MockPublisher) PublishRevocation(revocation credential.Revocation) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "PublishRevocation", revocation)
	ret0, _ := ret[0].(error)
	return ret0
}

// PublishRevocation indicates an expected call of PublishRevocation.
func (mr *MockPublisherMockRecorder) PublishRevocation(revocation interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "PublishRevocation", reflect.TypeOf((*MockPublisher)(nil).PublishRevocation), revocation)
}

// MockkeyResolver is a mock of keyResolver interface.
type MockkeyResolver struct {
	ctrl     *gomock.Controller
	recorder *MockkeyResolverMockRecorder
}

// MockkeyResolverMockRecorder is the mock recorder for MockkeyResolver.
type MockkeyResolverMockRecorder struct {
	mock *MockkeyResolver
}

// NewMockkeyResolver creates a new mock instance.
func NewMockkeyResolver(ctrl *gomock.Controller) *MockkeyResolver {
	mock := &MockkeyResolver{ctrl: ctrl}
	mock.recorder = &MockkeyResolverMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockkeyResolver) EXPECT() *MockkeyResolverMockRecorder {
	return m.recorder
}

// ResolveAssertionKey mocks base method.
func (m *MockkeyResolver) ResolveAssertionKey(issuerDID did.DID) (crypto.Key, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ResolveAssertionKey", issuerDID)
	ret0, _ := ret[0].(crypto.Key)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// ResolveAssertionKey indicates an expected call of ResolveAssertionKey.
func (mr *MockkeyResolverMockRecorder) ResolveAssertionKey(issuerDID interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ResolveAssertionKey", reflect.TypeOf((*MockkeyResolver)(nil).ResolveAssertionKey), issuerDID)
}

// MockIssuer is a mock of Issuer interface.
type MockIssuer struct {
	ctrl     *gomock.Controller
	recorder *MockIssuerMockRecorder
}

// MockIssuerMockRecorder is the mock recorder for MockIssuer.
type MockIssuerMockRecorder struct {
	mock *MockIssuer
}

// NewMockIssuer creates a new mock instance.
func NewMockIssuer(ctrl *gomock.Controller) *MockIssuer {
	mock := &MockIssuer{ctrl: ctrl}
	mock.recorder = &MockIssuerMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockIssuer) EXPECT() *MockIssuerMockRecorder {
	return m.recorder
}

// CredentialResolver mocks base method.
func (m *MockIssuer) CredentialResolver() StoreResolver {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "CredentialResolver")
	ret0, _ := ret[0].(StoreResolver)
	return ret0
}

// CredentialResolver indicates an expected call of CredentialResolver.
func (mr *MockIssuerMockRecorder) CredentialResolver() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CredentialResolver", reflect.TypeOf((*MockIssuer)(nil).CredentialResolver))
}

// Issue mocks base method.
func (m *MockIssuer) Issue(unsignedCredential vc.VerifiableCredential, publish, public bool) (*vc.VerifiableCredential, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Issue", unsignedCredential, publish, public)
	ret0, _ := ret[0].(*vc.VerifiableCredential)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Issue indicates an expected call of Issue.
func (mr *MockIssuerMockRecorder) Issue(unsignedCredential, publish, public interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Issue", reflect.TypeOf((*MockIssuer)(nil).Issue), unsignedCredential, publish, public)
}

// Revoke mocks base method.
func (m *MockIssuer) Revoke(credentialID go_did.URI) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Revoke", credentialID)
	ret0, _ := ret[0].(error)
	return ret0
}

// Revoke indicates an expected call of Revoke.
func (mr *MockIssuerMockRecorder) Revoke(credentialID interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Revoke", reflect.TypeOf((*MockIssuer)(nil).Revoke), credentialID)
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

// SearchCredential mocks base method.
func (m *MockStore) SearchCredential(context go_did.URI, credentialType string, issuer did.DID, subject *go_did.URI) ([]vc.VerifiableCredential, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "SearchCredential", context, credentialType, issuer, subject)
	ret0, _ := ret[0].([]vc.VerifiableCredential)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// SearchCredential indicates an expected call of SearchCredential.
func (mr *MockStoreMockRecorder) SearchCredential(context, credentialType, issuer, subject interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SearchCredential", reflect.TypeOf((*MockStore)(nil).SearchCredential), context, credentialType, issuer, subject)
}

// StoreCredential mocks base method.
func (m *MockStore) StoreCredential(vc vc.VerifiableCredential, validAt *time.Time) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "StoreCredential", vc, validAt)
	ret0, _ := ret[0].(error)
	return ret0
}

// StoreCredential indicates an expected call of StoreCredential.
func (mr *MockStoreMockRecorder) StoreCredential(vc, validAt interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "StoreCredential", reflect.TypeOf((*MockStore)(nil).StoreCredential), vc, validAt)
}

// StoreRevocation mocks base method.
func (m *MockStore) StoreRevocation(r credential.Revocation) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "StoreRevocation", r)
	ret0, _ := ret[0].(error)
	return ret0
}

// StoreRevocation indicates an expected call of StoreRevocation.
func (mr *MockStoreMockRecorder) StoreRevocation(r interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "StoreRevocation", reflect.TypeOf((*MockStore)(nil).StoreRevocation), r)
}

// MockStoreResolver is a mock of StoreResolver interface.
type MockStoreResolver struct {
	ctrl     *gomock.Controller
	recorder *MockStoreResolverMockRecorder
}

// MockStoreResolverMockRecorder is the mock recorder for MockStoreResolver.
type MockStoreResolverMockRecorder struct {
	mock *MockStoreResolver
}

// NewMockStoreResolver creates a new mock instance.
func NewMockStoreResolver(ctrl *gomock.Controller) *MockStoreResolver {
	mock := &MockStoreResolver{ctrl: ctrl}
	mock.recorder = &MockStoreResolverMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockStoreResolver) EXPECT() *MockStoreResolverMockRecorder {
	return m.recorder
}

// SearchCredential mocks base method.
func (m *MockStoreResolver) SearchCredential(context go_did.URI, credentialType string, issuer did.DID, subject *go_did.URI) ([]vc.VerifiableCredential, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "SearchCredential", context, credentialType, issuer, subject)
	ret0, _ := ret[0].([]vc.VerifiableCredential)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// SearchCredential indicates an expected call of SearchCredential.
func (mr *MockStoreResolverMockRecorder) SearchCredential(context, credentialType, issuer, subject interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SearchCredential", reflect.TypeOf((*MockStoreResolver)(nil).SearchCredential), context, credentialType, issuer, subject)
}

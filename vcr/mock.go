// Code generated by MockGen. DO NOT EDIT.
// Source: vcr/interface.go

// Package vcr is a generated GoMock package.
package vcr

import (
	reflect "reflect"
	time "time"

	gomock "github.com/golang/mock/gomock"
	ssi "github.com/nuts-foundation/go-did"
	vc "github.com/nuts-foundation/go-did/vc"
	concept "github.com/nuts-foundation/nuts-node/vcr/concept"
	credential "github.com/nuts-foundation/nuts-node/vcr/credential"
)

// MockConceptFinder is a mock of ConceptFinder interface.
type MockConceptFinder struct {
	ctrl     *gomock.Controller
	recorder *MockConceptFinderMockRecorder
}

// MockConceptFinderMockRecorder is the mock recorder for MockConceptFinder.
type MockConceptFinderMockRecorder struct {
	mock *MockConceptFinder
}

// NewMockConceptFinder creates a new mock instance.
func NewMockConceptFinder(ctrl *gomock.Controller) *MockConceptFinder {
	mock := &MockConceptFinder{ctrl: ctrl}
	mock.recorder = &MockConceptFinderMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockConceptFinder) EXPECT() *MockConceptFinderMockRecorder {
	return m.recorder
}

// Get mocks base method.
func (m *MockConceptFinder) Get(conceptName, subject string) (concept.Concept, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Get", conceptName, subject)
	ret0, _ := ret[0].(concept.Concept)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Get indicates an expected call of Get.
func (mr *MockConceptFinderMockRecorder) Get(conceptName, subject interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Get", reflect.TypeOf((*MockConceptFinder)(nil).Get), conceptName, subject)
}

// MockWriter is a mock of Writer interface.
type MockWriter struct {
	ctrl     *gomock.Controller
	recorder *MockWriterMockRecorder
}

// MockWriterMockRecorder is the mock recorder for MockWriter.
type MockWriterMockRecorder struct {
	mock *MockWriter
}

// NewMockWriter creates a new mock instance.
func NewMockWriter(ctrl *gomock.Controller) *MockWriter {
	mock := &MockWriter{ctrl: ctrl}
	mock.recorder = &MockWriterMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockWriter) EXPECT() *MockWriterMockRecorder {
	return m.recorder
}

// StoreCredential mocks base method.
func (m *MockWriter) StoreCredential(vc vc.VerifiableCredential) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "StoreCredential", vc)
	ret0, _ := ret[0].(error)
	return ret0
}

// StoreCredential indicates an expected call of StoreCredential.
func (mr *MockWriterMockRecorder) StoreCredential(vc interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "StoreCredential", reflect.TypeOf((*MockWriter)(nil).StoreCredential), vc)
}

// StoreRevocation mocks base method.
func (m *MockWriter) StoreRevocation(r credential.Revocation) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "StoreRevocation", r)
	ret0, _ := ret[0].(error)
	return ret0
}

// StoreRevocation indicates an expected call of StoreRevocation.
func (mr *MockWriterMockRecorder) StoreRevocation(r interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "StoreRevocation", reflect.TypeOf((*MockWriter)(nil).StoreRevocation), r)
}

// MockTrustManager is a mock of TrustManager interface.
type MockTrustManager struct {
	ctrl     *gomock.Controller
	recorder *MockTrustManagerMockRecorder
}

// MockTrustManagerMockRecorder is the mock recorder for MockTrustManager.
type MockTrustManagerMockRecorder struct {
	mock *MockTrustManager
}

// NewMockTrustManager creates a new mock instance.
func NewMockTrustManager(ctrl *gomock.Controller) *MockTrustManager {
	mock := &MockTrustManager{ctrl: ctrl}
	mock.recorder = &MockTrustManagerMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockTrustManager) EXPECT() *MockTrustManagerMockRecorder {
	return m.recorder
}

// Trust mocks base method.
func (m *MockTrustManager) Trust(credentialType, issuer ssi.URI) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Trust", credentialType, issuer)
	ret0, _ := ret[0].(error)
	return ret0
}

// Trust indicates an expected call of Trust.
func (mr *MockTrustManagerMockRecorder) Trust(credentialType, issuer interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Trust", reflect.TypeOf((*MockTrustManager)(nil).Trust), credentialType, issuer)
}

// Trusted mocks base method.
func (m *MockTrustManager) Trusted(credentialType ssi.URI) ([]ssi.URI, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Trusted", credentialType)
	ret0, _ := ret[0].([]ssi.URI)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Trusted indicates an expected call of Trusted.
func (mr *MockTrustManagerMockRecorder) Trusted(credentialType interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Trusted", reflect.TypeOf((*MockTrustManager)(nil).Trusted), credentialType)
}

// Untrust mocks base method.
func (m *MockTrustManager) Untrust(credentialType, issuer ssi.URI) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Untrust", credentialType, issuer)
	ret0, _ := ret[0].(error)
	return ret0
}

// Untrust indicates an expected call of Untrust.
func (mr *MockTrustManagerMockRecorder) Untrust(credentialType, issuer interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Untrust", reflect.TypeOf((*MockTrustManager)(nil).Untrust), credentialType, issuer)
}

// Untrusted mocks base method.
func (m *MockTrustManager) Untrusted(credentialType ssi.URI) ([]ssi.URI, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Untrusted", credentialType)
	ret0, _ := ret[0].([]ssi.URI)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Untrusted indicates an expected call of Untrusted.
func (mr *MockTrustManagerMockRecorder) Untrusted(credentialType interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Untrusted", reflect.TypeOf((*MockTrustManager)(nil).Untrusted), credentialType)
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

// Registry mocks base method.
func (m *MockResolver) Registry() concept.Registry {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Registry")
	ret0, _ := ret[0].(concept.Registry)
	return ret0
}

// Registry indicates an expected call of Registry.
func (mr *MockResolverMockRecorder) Registry() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Registry", reflect.TypeOf((*MockResolver)(nil).Registry))
}

// Search mocks base method.
func (m *MockResolver) Search(query concept.Query) ([]vc.VerifiableCredential, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Search", query)
	ret0, _ := ret[0].([]vc.VerifiableCredential)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Search indicates an expected call of Search.
func (mr *MockResolverMockRecorder) Search(query interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Search", reflect.TypeOf((*MockResolver)(nil).Search), query)
}

// Verify mocks base method.
func (m *MockResolver) Verify(vcToVerify vc.VerifiableCredential, at *time.Time) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Verify", vcToVerify, at)
	ret0, _ := ret[0].(error)
	return ret0
}

// Verify indicates an expected call of Verify.
func (mr *MockResolverMockRecorder) Verify(vcToVerify, at interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Verify", reflect.TypeOf((*MockResolver)(nil).Verify), vcToVerify, at)
}

// MockVCR is a mock of VCR interface.
type MockVCR struct {
	ctrl     *gomock.Controller
	recorder *MockVCRMockRecorder
}

// MockVCRMockRecorder is the mock recorder for MockVCR.
type MockVCRMockRecorder struct {
	mock *MockVCR
}

// NewMockVCR creates a new mock instance.
func NewMockVCR(ctrl *gomock.Controller) *MockVCR {
	mock := &MockVCR{ctrl: ctrl}
	mock.recorder = &MockVCRMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockVCR) EXPECT() *MockVCRMockRecorder {
	return m.recorder
}

// Get mocks base method.
func (m *MockVCR) Get(conceptName, subject string) (concept.Concept, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Get", conceptName, subject)
	ret0, _ := ret[0].(concept.Concept)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Get indicates an expected call of Get.
func (mr *MockVCRMockRecorder) Get(conceptName, subject interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Get", reflect.TypeOf((*MockVCR)(nil).Get), conceptName, subject)
}

// Issue mocks base method.
func (m *MockVCR) Issue(vcToIssue vc.VerifiableCredential) (*vc.VerifiableCredential, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Issue", vcToIssue)
	ret0, _ := ret[0].(*vc.VerifiableCredential)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Issue indicates an expected call of Issue.
func (mr *MockVCRMockRecorder) Issue(vcToIssue interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Issue", reflect.TypeOf((*MockVCR)(nil).Issue), vcToIssue)
}

// Registry mocks base method.
func (m *MockVCR) Registry() concept.Registry {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Registry")
	ret0, _ := ret[0].(concept.Registry)
	return ret0
}

// Registry indicates an expected call of Registry.
func (mr *MockVCRMockRecorder) Registry() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Registry", reflect.TypeOf((*MockVCR)(nil).Registry))
}

// Resolve mocks base method.
func (m *MockVCR) Resolve(ID ssi.URI) (*vc.VerifiableCredential, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Resolve", ID)
	ret0, _ := ret[0].(*vc.VerifiableCredential)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Resolve indicates an expected call of Resolve.
func (mr *MockVCRMockRecorder) Resolve(ID interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Resolve", reflect.TypeOf((*MockVCR)(nil).Resolve), ID)
}

// Revoke mocks base method.
func (m *MockVCR) Revoke(ID ssi.URI) (*credential.Revocation, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Revoke", ID)
	ret0, _ := ret[0].(*credential.Revocation)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Revoke indicates an expected call of Revoke.
func (mr *MockVCRMockRecorder) Revoke(ID interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Revoke", reflect.TypeOf((*MockVCR)(nil).Revoke), ID)
}

// Search mocks base method.
func (m *MockVCR) Search(query concept.Query) ([]vc.VerifiableCredential, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Search", query)
	ret0, _ := ret[0].([]vc.VerifiableCredential)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Search indicates an expected call of Search.
func (mr *MockVCRMockRecorder) Search(query interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Search", reflect.TypeOf((*MockVCR)(nil).Search), query)
}

// StoreCredential mocks base method.
func (m *MockVCR) StoreCredential(vc vc.VerifiableCredential) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "StoreCredential", vc)
	ret0, _ := ret[0].(error)
	return ret0
}

// StoreCredential indicates an expected call of StoreCredential.
func (mr *MockVCRMockRecorder) StoreCredential(vc interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "StoreCredential", reflect.TypeOf((*MockVCR)(nil).StoreCredential), vc)
}

// StoreRevocation mocks base method.
func (m *MockVCR) StoreRevocation(r credential.Revocation) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "StoreRevocation", r)
	ret0, _ := ret[0].(error)
	return ret0
}

// StoreRevocation indicates an expected call of StoreRevocation.
func (mr *MockVCRMockRecorder) StoreRevocation(r interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "StoreRevocation", reflect.TypeOf((*MockVCR)(nil).StoreRevocation), r)
}

// Trust mocks base method.
func (m *MockVCR) Trust(credentialType, issuer ssi.URI) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Trust", credentialType, issuer)
	ret0, _ := ret[0].(error)
	return ret0
}

// Trust indicates an expected call of Trust.
func (mr *MockVCRMockRecorder) Trust(credentialType, issuer interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Trust", reflect.TypeOf((*MockVCR)(nil).Trust), credentialType, issuer)
}

// Trusted mocks base method.
func (m *MockVCR) Trusted(credentialType ssi.URI) ([]ssi.URI, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Trusted", credentialType)
	ret0, _ := ret[0].([]ssi.URI)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Trusted indicates an expected call of Trusted.
func (mr *MockVCRMockRecorder) Trusted(credentialType interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Trusted", reflect.TypeOf((*MockVCR)(nil).Trusted), credentialType)
}

// Untrust mocks base method.
func (m *MockVCR) Untrust(credentialType, issuer ssi.URI) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Untrust", credentialType, issuer)
	ret0, _ := ret[0].(error)
	return ret0
}

// Untrust indicates an expected call of Untrust.
func (mr *MockVCRMockRecorder) Untrust(credentialType, issuer interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Untrust", reflect.TypeOf((*MockVCR)(nil).Untrust), credentialType, issuer)
}

// Untrusted mocks base method.
func (m *MockVCR) Untrusted(credentialType ssi.URI) ([]ssi.URI, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Untrusted", credentialType)
	ret0, _ := ret[0].([]ssi.URI)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Untrusted indicates an expected call of Untrusted.
func (mr *MockVCRMockRecorder) Untrusted(credentialType interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Untrusted", reflect.TypeOf((*MockVCR)(nil).Untrusted), credentialType)
}

// Verify mocks base method.
func (m *MockVCR) Verify(vcToVerify vc.VerifiableCredential, at *time.Time) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Verify", vcToVerify, at)
	ret0, _ := ret[0].(error)
	return ret0
}

// Verify indicates an expected call of Verify.
func (mr *MockVCRMockRecorder) Verify(vcToVerify, at interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Verify", reflect.TypeOf((*MockVCR)(nil).Verify), vcToVerify, at)
}

// Code generated by MockGen. DO NOT EDIT.
// Source: vcr/interface.go

// Package vcr is a generated GoMock package.
package vcr

import (
	context "context"
	reflect "reflect"
	time "time"

	gomock "github.com/golang/mock/gomock"
	go_did "github.com/nuts-foundation/go-did"
	did "github.com/nuts-foundation/go-did/did"
	vc "github.com/nuts-foundation/go-did/vc"
	holder "github.com/nuts-foundation/nuts-node/vcr/holder"
	issuer "github.com/nuts-foundation/nuts-node/vcr/issuer"
	verifier "github.com/nuts-foundation/nuts-node/vcr/verifier"
)

// MockFinder is a mock of Finder interface.
type MockFinder struct {
	ctrl     *gomock.Controller
	recorder *MockFinderMockRecorder
}

// MockFinderMockRecorder is the mock recorder for MockFinder.
type MockFinderMockRecorder struct {
	mock *MockFinder
}

// NewMockFinder creates a new mock instance.
func NewMockFinder(ctrl *gomock.Controller) *MockFinder {
	mock := &MockFinder{ctrl: ctrl}
	mock.recorder = &MockFinderMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockFinder) EXPECT() *MockFinderMockRecorder {
	return m.recorder
}

// Search mocks base method.
func (m *MockFinder) Search(ctx context.Context, searchTerms []SearchTerm, allowUntrusted bool, resolveTime *time.Time) ([]vc.VerifiableCredential, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Search", ctx, searchTerms, allowUntrusted, resolveTime)
	ret0, _ := ret[0].([]vc.VerifiableCredential)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Search indicates an expected call of Search.
func (mr *MockFinderMockRecorder) Search(ctx, searchTerms, allowUntrusted, resolveTime interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Search", reflect.TypeOf((*MockFinder)(nil).Search), ctx, searchTerms, allowUntrusted, resolveTime)
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
func (m *MockTrustManager) Trust(credentialType, issuer go_did.URI) error {
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
func (m *MockTrustManager) Trusted(credentialType go_did.URI) ([]go_did.URI, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Trusted", credentialType)
	ret0, _ := ret[0].([]go_did.URI)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Trusted indicates an expected call of Trusted.
func (mr *MockTrustManagerMockRecorder) Trusted(credentialType interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Trusted", reflect.TypeOf((*MockTrustManager)(nil).Trusted), credentialType)
}

// Untrust mocks base method.
func (m *MockTrustManager) Untrust(credentialType, issuer go_did.URI) error {
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
func (m *MockTrustManager) Untrusted(credentialType go_did.URI) ([]go_did.URI, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Untrusted", credentialType)
	ret0, _ := ret[0].([]go_did.URI)
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

// Resolve mocks base method.
func (m *MockResolver) Resolve(ID go_did.URI, resolveTime *time.Time) (*vc.VerifiableCredential, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Resolve", ID, resolveTime)
	ret0, _ := ret[0].(*vc.VerifiableCredential)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Resolve indicates an expected call of Resolve.
func (mr *MockResolverMockRecorder) Resolve(ID, resolveTime interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Resolve", reflect.TypeOf((*MockResolver)(nil).Resolve), ID, resolveTime)
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

// GetOIDCIssuer mocks base method.
func (m *MockVCR) GetOIDCIssuer(id did.DID) issuer.OIDCIssuer {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetOIDCIssuer", id)
	ret0, _ := ret[0].(issuer.OIDCIssuer)
	return ret0
}

// GetOIDCIssuer indicates an expected call of GetOIDCIssuer.
func (mr *MockVCRMockRecorder) GetOIDCIssuer(id interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetOIDCIssuer", reflect.TypeOf((*MockVCR)(nil).GetOIDCIssuer), id)
}

// GetOIDCWallet mocks base method.
func (m *MockVCR) GetOIDCWallet(id did.DID) holder.OIDCWallet {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetOIDCWallet", id)
	ret0, _ := ret[0].(holder.OIDCWallet)
	return ret0
}

// GetOIDCWallet indicates an expected call of GetOIDCWallet.
func (mr *MockVCRMockRecorder) GetOIDCWallet(id interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetOIDCWallet", reflect.TypeOf((*MockVCR)(nil).GetOIDCWallet), id)
}

// Holder mocks base method.
func (m *MockVCR) Holder() holder.Holder {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Holder")
	ret0, _ := ret[0].(holder.Holder)
	return ret0
}

// Holder indicates an expected call of Holder.
func (mr *MockVCRMockRecorder) Holder() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Holder", reflect.TypeOf((*MockVCR)(nil).Holder))
}

// Issuer mocks base method.
func (m *MockVCR) Issuer() issuer.Issuer {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Issuer")
	ret0, _ := ret[0].(issuer.Issuer)
	return ret0
}

// Issuer indicates an expected call of Issuer.
func (mr *MockVCRMockRecorder) Issuer() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Issuer", reflect.TypeOf((*MockVCR)(nil).Issuer))
}

// Resolve mocks base method.
func (m *MockVCR) Resolve(ID go_did.URI, resolveTime *time.Time) (*vc.VerifiableCredential, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Resolve", ID, resolveTime)
	ret0, _ := ret[0].(*vc.VerifiableCredential)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Resolve indicates an expected call of Resolve.
func (mr *MockVCRMockRecorder) Resolve(ID, resolveTime interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Resolve", reflect.TypeOf((*MockVCR)(nil).Resolve), ID, resolveTime)
}

// Search mocks base method.
func (m *MockVCR) Search(ctx context.Context, searchTerms []SearchTerm, allowUntrusted bool, resolveTime *time.Time) ([]vc.VerifiableCredential, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Search", ctx, searchTerms, allowUntrusted, resolveTime)
	ret0, _ := ret[0].([]vc.VerifiableCredential)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Search indicates an expected call of Search.
func (mr *MockVCRMockRecorder) Search(ctx, searchTerms, allowUntrusted, resolveTime interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Search", reflect.TypeOf((*MockVCR)(nil).Search), ctx, searchTerms, allowUntrusted, resolveTime)
}

// StoreCredential mocks base method.
func (m *MockVCR) StoreCredential(vc vc.VerifiableCredential, validAt *time.Time) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "StoreCredential", vc, validAt)
	ret0, _ := ret[0].(error)
	return ret0
}

// StoreCredential indicates an expected call of StoreCredential.
func (mr *MockVCRMockRecorder) StoreCredential(vc, validAt interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "StoreCredential", reflect.TypeOf((*MockVCR)(nil).StoreCredential), vc, validAt)
}

// Trust mocks base method.
func (m *MockVCR) Trust(credentialType, issuer go_did.URI) error {
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
func (m *MockVCR) Trusted(credentialType go_did.URI) ([]go_did.URI, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Trusted", credentialType)
	ret0, _ := ret[0].([]go_did.URI)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Trusted indicates an expected call of Trusted.
func (mr *MockVCRMockRecorder) Trusted(credentialType interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Trusted", reflect.TypeOf((*MockVCR)(nil).Trusted), credentialType)
}

// Untrust mocks base method.
func (m *MockVCR) Untrust(credentialType, issuer go_did.URI) error {
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
func (m *MockVCR) Untrusted(credentialType go_did.URI) ([]go_did.URI, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Untrusted", credentialType)
	ret0, _ := ret[0].([]go_did.URI)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Untrusted indicates an expected call of Untrusted.
func (mr *MockVCRMockRecorder) Untrusted(credentialType interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Untrusted", reflect.TypeOf((*MockVCR)(nil).Untrusted), credentialType)
}

// Verifier mocks base method.
func (m *MockVCR) Verifier() verifier.Verifier {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Verifier")
	ret0, _ := ret[0].(verifier.Verifier)
	return ret0
}

// Verifier indicates an expected call of Verifier.
func (mr *MockVCRMockRecorder) Verifier() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Verifier", reflect.TypeOf((*MockVCR)(nil).Verifier))
}

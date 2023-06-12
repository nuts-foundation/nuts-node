// Code generated by MockGen. DO NOT EDIT.
// Source: pki/interface.go

// Package pki is a generated GoMock package.
package pki

import (
	tls "crypto/tls"
	x509 "crypto/x509"
	reflect "reflect"
	time "time"

	gomock "github.com/golang/mock/gomock"
	core "github.com/nuts-foundation/nuts-node/core"
)

// MockDenylist is a mock of Denylist interface.
type MockDenylist struct {
	ctrl     *gomock.Controller
	recorder *MockDenylistMockRecorder
}

// MockDenylistMockRecorder is the mock recorder for MockDenylist.
type MockDenylistMockRecorder struct {
	mock *MockDenylist
}

// NewMockDenylist creates a new mock instance.
func NewMockDenylist(ctrl *gomock.Controller) *MockDenylist {
	mock := &MockDenylist{ctrl: ctrl}
	mock.recorder = &MockDenylistMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockDenylist) EXPECT() *MockDenylistMockRecorder {
	return m.recorder
}

// LastUpdated mocks base method.
func (m *MockDenylist) LastUpdated() time.Time {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "LastUpdated")
	ret0, _ := ret[0].(time.Time)
	return ret0
}

// LastUpdated indicates an expected call of LastUpdated.
func (mr *MockDenylistMockRecorder) LastUpdated() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "LastUpdated", reflect.TypeOf((*MockDenylist)(nil).LastUpdated))
}

// Subscribe mocks base method.
func (m *MockDenylist) Subscribe(f func()) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "Subscribe", f)
}

// Subscribe indicates an expected call of Subscribe.
func (mr *MockDenylistMockRecorder) Subscribe(f interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Subscribe", reflect.TypeOf((*MockDenylist)(nil).Subscribe), f)
}

// URL mocks base method.
func (m *MockDenylist) URL() string {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "URL")
	ret0, _ := ret[0].(string)
	return ret0
}

// URL indicates an expected call of URL.
func (mr *MockDenylistMockRecorder) URL() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "URL", reflect.TypeOf((*MockDenylist)(nil).URL))
}

// Update mocks base method.
func (m *MockDenylist) Update() error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Update")
	ret0, _ := ret[0].(error)
	return ret0
}

// Update indicates an expected call of Update.
func (mr *MockDenylistMockRecorder) Update() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Update", reflect.TypeOf((*MockDenylist)(nil).Update))
}

// ValidateCert mocks base method.
func (m *MockDenylist) ValidateCert(cert *x509.Certificate) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ValidateCert", cert)
	ret0, _ := ret[0].(error)
	return ret0
}

// ValidateCert indicates an expected call of ValidateCert.
func (mr *MockDenylistMockRecorder) ValidateCert(cert interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ValidateCert", reflect.TypeOf((*MockDenylist)(nil).ValidateCert), cert)
}

// MockValidator is a mock of Validator interface.
type MockValidator struct {
	ctrl     *gomock.Controller
	recorder *MockValidatorMockRecorder
}

// MockValidatorMockRecorder is the mock recorder for MockValidator.
type MockValidatorMockRecorder struct {
	mock *MockValidator
}

// NewMockValidator creates a new mock instance.
func NewMockValidator(ctrl *gomock.Controller) *MockValidator {
	mock := &MockValidator{ctrl: ctrl}
	mock.recorder = &MockValidatorMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockValidator) EXPECT() *MockValidatorMockRecorder {
	return m.recorder
}

// AddTruststore mocks base method.
func (m *MockValidator) AddTruststore(chain []*x509.Certificate) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "AddTruststore", chain)
	ret0, _ := ret[0].(error)
	return ret0
}

// AddTruststore indicates an expected call of AddTruststore.
func (mr *MockValidatorMockRecorder) AddTruststore(chain interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "AddTruststore", reflect.TypeOf((*MockValidator)(nil).AddTruststore), chain)
}

// SetVerifyPeerCertificateFunc mocks base method.
func (m *MockValidator) SetVerifyPeerCertificateFunc(config *tls.Config) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "SetVerifyPeerCertificateFunc", config)
	ret0, _ := ret[0].(error)
	return ret0
}

// SetVerifyPeerCertificateFunc indicates an expected call of SetVerifyPeerCertificateFunc.
func (mr *MockValidatorMockRecorder) SetVerifyPeerCertificateFunc(config interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SetVerifyPeerCertificateFunc", reflect.TypeOf((*MockValidator)(nil).SetVerifyPeerCertificateFunc), config)
}

// SubscribeDenied mocks base method.
func (m *MockValidator) SubscribeDenied(f func()) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "SubscribeDenied", f)
}

// SubscribeDenied indicates an expected call of SubscribeDenied.
func (mr *MockValidatorMockRecorder) SubscribeDenied(f interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SubscribeDenied", reflect.TypeOf((*MockValidator)(nil).SubscribeDenied), f)
}

// Validate mocks base method.
func (m *MockValidator) Validate(chain []*x509.Certificate) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Validate", chain)
	ret0, _ := ret[0].(error)
	return ret0
}

// Validate indicates an expected call of Validate.
func (mr *MockValidatorMockRecorder) Validate(chain interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Validate", reflect.TypeOf((*MockValidator)(nil).Validate), chain)
}

// MockProvider is a mock of Provider interface.
type MockProvider struct {
	ctrl     *gomock.Controller
	recorder *MockProviderMockRecorder
}

// MockProviderMockRecorder is the mock recorder for MockProvider.
type MockProviderMockRecorder struct {
	mock *MockProvider
}

// NewMockProvider creates a new mock instance.
func NewMockProvider(ctrl *gomock.Controller) *MockProvider {
	mock := &MockProvider{ctrl: ctrl}
	mock.recorder = &MockProviderMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockProvider) EXPECT() *MockProviderMockRecorder {
	return m.recorder
}

// AddTruststore mocks base method.
func (m *MockProvider) AddTruststore(chain []*x509.Certificate) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "AddTruststore", chain)
	ret0, _ := ret[0].(error)
	return ret0
}

// AddTruststore indicates an expected call of AddTruststore.
func (mr *MockProviderMockRecorder) AddTruststore(chain interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "AddTruststore", reflect.TypeOf((*MockProvider)(nil).AddTruststore), chain)
}

// CreateTLSConfig mocks base method.
func (m *MockProvider) CreateTLSConfig(cfg core.TLSConfig) (*tls.Config, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "CreateTLSConfig", cfg)
	ret0, _ := ret[0].(*tls.Config)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// CreateTLSConfig indicates an expected call of CreateTLSConfig.
func (mr *MockProviderMockRecorder) CreateTLSConfig(cfg interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CreateTLSConfig", reflect.TypeOf((*MockProvider)(nil).CreateTLSConfig), cfg)
}

// SetVerifyPeerCertificateFunc mocks base method.
func (m *MockProvider) SetVerifyPeerCertificateFunc(config *tls.Config) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "SetVerifyPeerCertificateFunc", config)
	ret0, _ := ret[0].(error)
	return ret0
}

// SetVerifyPeerCertificateFunc indicates an expected call of SetVerifyPeerCertificateFunc.
func (mr *MockProviderMockRecorder) SetVerifyPeerCertificateFunc(config interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SetVerifyPeerCertificateFunc", reflect.TypeOf((*MockProvider)(nil).SetVerifyPeerCertificateFunc), config)
}

// SubscribeDenied mocks base method.
func (m *MockProvider) SubscribeDenied(f func()) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "SubscribeDenied", f)
}

// SubscribeDenied indicates an expected call of SubscribeDenied.
func (mr *MockProviderMockRecorder) SubscribeDenied(f interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SubscribeDenied", reflect.TypeOf((*MockProvider)(nil).SubscribeDenied), f)
}

// Validate mocks base method.
func (m *MockProvider) Validate(chain []*x509.Certificate) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Validate", chain)
	ret0, _ := ret[0].(error)
	return ret0
}

// Validate indicates an expected call of Validate.
func (mr *MockProviderMockRecorder) Validate(chain interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Validate", reflect.TypeOf((*MockProvider)(nil).Validate), chain)
}

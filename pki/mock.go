// Code generated by MockGen. DO NOT EDIT.
// Source: pki/validator.go

// Package pki is a generated GoMock package.
package pki

import (
	tls "crypto/tls"
	x509 "crypto/x509"
	reflect "reflect"

	gomock "github.com/golang/mock/gomock"
)

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

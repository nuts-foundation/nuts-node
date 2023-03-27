// Code generated by MockGen. DO NOT EDIT.
// Source: crl/validator2.go

// Package crl is a generated GoMock package.
package crl

import (
	context "context"
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

// IsRevoked mocks base method.
func (m *MockValidator) IsRevoked(certificate *x509.Certificate) (bool, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "IsRevoked", certificate)
	ret0, _ := ret[0].(bool)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// IsRevoked indicates an expected call of IsRevoked.
func (mr *MockValidatorMockRecorder) IsRevoked(certificate interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "IsRevoked", reflect.TypeOf((*MockValidator)(nil).IsRevoked), certificate)
}


// SetValidatePeerCertificateFunc mocks base method.
func (m *MockValidator) SetValidatePeerCertificateFunc(config *tls.Config) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "SetValidatePeerCertificateFunc", config)
	ret0, _ := ret[0].(error)
	return ret0
}

// SetValidatePeerCertificateFunc indicates an expected call of SetValidatePeerCertificateFunc.
func (mr *MockValidatorMockRecorder) SetValidatePeerCertificateFunc(config interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SetValidatePeerCertificateFunc", reflect.TypeOf((*MockValidator)(nil).SetValidatePeerCertificateFunc), config)
}

// Start mocks base method.
func (m *MockValidator) Start(ctx context.Context) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "Start", ctx)
}

// Start indicates an expected call of Start.
func (mr *MockValidatorMockRecorder) Start(ctx interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Start", reflect.TypeOf((*MockValidator)(nil).Start), ctx)
}

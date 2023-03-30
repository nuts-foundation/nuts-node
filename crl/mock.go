// Code generated by MockGen. DO NOT EDIT.
// Source: crl/validator.go

// Package crl is a generated GoMock package.
package crl

import (
	context "context"
	x509 "crypto/x509"
	big "math/big"
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
func (m *MockValidator) IsRevoked(issuer string, serialNumber *big.Int) bool {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "IsRevoked", issuer, serialNumber)
	ret0, _ := ret[0].(bool)
	return ret0
}

// IsRevoked indicates an expected call of IsRevoked.
func (mr *MockValidatorMockRecorder) IsRevoked(issuer, serialNumber interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "IsRevoked", reflect.TypeOf((*MockValidator)(nil).IsRevoked), issuer, serialNumber)
}

// IsSynced mocks base method.
func (m *MockValidator) IsSynced(maxOffsetDays int) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "IsSynced", maxOffsetDays)
	ret0, _ := ret[0].(error)
	return ret0
}

// IsSynced indicates an expected call of IsSynced.
func (mr *MockValidatorMockRecorder) IsSynced(maxOffsetDays interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "IsSynced", reflect.TypeOf((*MockValidator)(nil).IsSynced), maxOffsetDays)
}

// Sync mocks base method.
func (m *MockValidator) Sync() error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Sync")
	ret0, _ := ret[0].(error)
	return ret0
}

// Sync indicates an expected call of Sync.
func (mr *MockValidatorMockRecorder) Sync() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Sync", reflect.TypeOf((*MockValidator)(nil).Sync))
}

// SyncLoop mocks base method.
func (m *MockValidator) SyncLoop(ctx context.Context) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "SyncLoop", ctx)
}

// SyncLoop indicates an expected call of SyncLoop.
func (mr *MockValidatorMockRecorder) SyncLoop(ctx interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SyncLoop", reflect.TypeOf((*MockValidator)(nil).SyncLoop), ctx)
}

// VerifyPeerCertificateFunction mocks base method.
func (m *MockValidator) VerifyPeerCertificateFunction(maxValidityDays int) func([][]byte, [][]*x509.Certificate) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "VerifyPeerCertificateFunction", maxValidityDays)
	ret0, _ := ret[0].(func([][]byte, [][]*x509.Certificate) error)
	return ret0
}

// VerifyPeerCertificateFunction indicates an expected call of VerifyPeerCertificateFunction.
func (mr *MockValidatorMockRecorder) VerifyPeerCertificateFunction(maxValidityDays interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "VerifyPeerCertificateFunction", reflect.TypeOf((*MockValidator)(nil).VerifyPeerCertificateFunction), maxValidityDays)
}

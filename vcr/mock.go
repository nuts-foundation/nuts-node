// Code generated by MockGen. DO NOT EDIT.
// Source: vcr/interface.go

// Package vcr is a generated GoMock package.
package vcr

import (
	reflect "reflect"
	time "time"

	gomock "github.com/golang/mock/gomock"
	did "github.com/nuts-foundation/go-did"
	concept "github.com/nuts-foundation/nuts-node/vcr/concept"
)

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

// Write mocks base method.
func (m *MockWriter) Write(vc did.VerifiableCredential) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Write", vc)
	ret0, _ := ret[0].(error)
	return ret0
}

// Write indicates an expected call of Write.
func (mr *MockWriterMockRecorder) Write(vc interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Write", reflect.TypeOf((*MockWriter)(nil).Write), vc)
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

// Issue mocks base method.
func (m *MockVCR) Issue(vc did.VerifiableCredential) (*did.VerifiableCredential, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Issue", vc)
	ret0, _ := ret[0].(*did.VerifiableCredential)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Issue indicates an expected call of Issue.
func (mr *MockVCRMockRecorder) Issue(vc interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Issue", reflect.TypeOf((*MockVCR)(nil).Issue), vc)
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
func (m *MockVCR) Resolve(ID string) (did.VerifiableCredential, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Resolve", ID)
	ret0, _ := ret[0].(did.VerifiableCredential)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Resolve indicates an expected call of Resolve.
func (mr *MockVCRMockRecorder) Resolve(ID interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Resolve", reflect.TypeOf((*MockVCR)(nil).Resolve), ID)
}

// Search mocks base method.
func (m *MockVCR) Search(query concept.Query) ([]did.VerifiableCredential, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Search", query)
	ret0, _ := ret[0].([]did.VerifiableCredential)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Search indicates an expected call of Search.
func (mr *MockVCRMockRecorder) Search(query interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Search", reflect.TypeOf((*MockVCR)(nil).Search), query)
}

// Verify mocks base method.
func (m *MockVCR) Verify(vc did.VerifiableCredential, at *time.Time) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Verify", vc, at)
	ret0, _ := ret[0].(error)
	return ret0
}

// Verify indicates an expected call of Verify.
func (mr *MockVCRMockRecorder) Verify(vc, at interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Verify", reflect.TypeOf((*MockVCR)(nil).Verify), vc, at)
}

// Write mocks base method.
func (m *MockVCR) Write(vc did.VerifiableCredential) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Write", vc)
	ret0, _ := ret[0].(error)
	return ret0
}

// Write indicates an expected call of Write.
func (mr *MockVCRMockRecorder) Write(vc interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Write", reflect.TypeOf((*MockVCR)(nil).Write), vc)
}

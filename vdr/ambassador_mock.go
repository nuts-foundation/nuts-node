// Code generated by MockGen. DO NOT EDIT.
// Source: vdr/ambassador.go

// Package vdr is a generated GoMock package.
package vdr

import (
	reflect "reflect"

	gomock "go.uber.org/mock/gomock"
)

// MockAmbassador is a mock of Ambassador interface.
type MockAmbassador struct {
	ctrl     *gomock.Controller
	recorder *MockAmbassadorMockRecorder
}

// MockAmbassadorMockRecorder is the mock recorder for MockAmbassador.
type MockAmbassadorMockRecorder struct {
	mock *MockAmbassador
}

// NewMockAmbassador creates a new mock instance.
func NewMockAmbassador(ctrl *gomock.Controller) *MockAmbassador {
	mock := &MockAmbassador{ctrl: ctrl}
	mock.recorder = &MockAmbassadorMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockAmbassador) EXPECT() *MockAmbassadorMockRecorder {
	return m.recorder
}

// Configure mocks base method.
func (m *MockAmbassador) Configure() error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Configure")
	ret0, _ := ret[0].(error)
	return ret0
}

// Configure indicates an expected call of Configure.
func (mr *MockAmbassadorMockRecorder) Configure() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Configure", reflect.TypeOf((*MockAmbassador)(nil).Configure))
}

// Start mocks base method.
func (m *MockAmbassador) Start() error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Start")
	ret0, _ := ret[0].(error)
	return ret0
}

// Start indicates an expected call of Start.
func (mr *MockAmbassadorMockRecorder) Start() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Start", reflect.TypeOf((*MockAmbassador)(nil).Start))
}

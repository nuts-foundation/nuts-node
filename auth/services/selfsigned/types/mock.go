// Code generated by MockGen. DO NOT EDIT.
// Source: auth/services/selfsigned/types/types.go

// Package types is a generated GoMock package.
package types

import (
	reflect "reflect"

	gomock "github.com/golang/mock/gomock"
)

// MockSessionStore is a mock of SessionStore interface.
type MockSessionStore struct {
	ctrl     *gomock.Controller
	recorder *MockSessionStoreMockRecorder
}

// MockSessionStoreMockRecorder is the mock recorder for MockSessionStore.
type MockSessionStoreMockRecorder struct {
	mock *MockSessionStore
}

// NewMockSessionStore creates a new mock instance.
func NewMockSessionStore(ctrl *gomock.Controller) *MockSessionStore {
	mock := &MockSessionStore{ctrl: ctrl}
	mock.recorder = &MockSessionStoreMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockSessionStore) EXPECT() *MockSessionStoreMockRecorder {
	return m.recorder
}

// CheckAndSetStatus mocks base method.
func (m *MockSessionStore) CheckAndSetStatus(sessionID, expectedStatus, status string) bool {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "CheckAndSetStatus", sessionID, expectedStatus, status)
	ret0, _ := ret[0].(bool)
	return ret0
}

// CheckAndSetStatus indicates an expected call of CheckAndSetStatus.
func (mr *MockSessionStoreMockRecorder) CheckAndSetStatus(sessionID, expectedStatus, status interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CheckAndSetStatus", reflect.TypeOf((*MockSessionStore)(nil).CheckAndSetStatus), sessionID, expectedStatus, status)
}

// Delete mocks base method.
func (m *MockSessionStore) Delete(sessionID string) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "Delete", sessionID)
}

// Delete indicates an expected call of Delete.
func (mr *MockSessionStoreMockRecorder) Delete(sessionID interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Delete", reflect.TypeOf((*MockSessionStore)(nil).Delete), sessionID)
}

// Load mocks base method.
func (m *MockSessionStore) Load(sessionID string) (Session, bool) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Load", sessionID)
	ret0, _ := ret[0].(Session)
	ret1, _ := ret[1].(bool)
	return ret0, ret1
}

// Load indicates an expected call of Load.
func (mr *MockSessionStoreMockRecorder) Load(sessionID interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Load", reflect.TypeOf((*MockSessionStore)(nil).Load), sessionID)
}

// Store mocks base method.
func (m *MockSessionStore) Store(sessionID string, session Session) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "Store", sessionID, session)
}

// Store indicates an expected call of Store.
func (mr *MockSessionStoreMockRecorder) Store(sessionID, session interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Store", reflect.TypeOf((*MockSessionStore)(nil).Store), sessionID, session)
}

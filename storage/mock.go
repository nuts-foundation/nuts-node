// Code generated by MockGen. DO NOT EDIT.
// Source: storage/interface.go

// Package storage is a generated GoMock package.
package storage

import (
	reflect "reflect"

	gomock "github.com/golang/mock/gomock"
	api "github.com/nuts-foundation/go-storage/api"
	core "github.com/nuts-foundation/nuts-node/core"
)

// MockEngine is a mock of Engine interface.
type MockEngine struct {
	ctrl     *gomock.Controller
	recorder *MockEngineMockRecorder
}

// MockEngineMockRecorder is the mock recorder for MockEngine.
type MockEngineMockRecorder struct {
	mock *MockEngine
}

// NewMockEngine creates a new mock instance.
func NewMockEngine(ctrl *gomock.Controller) *MockEngine {
	mock := &MockEngine{ctrl: ctrl}
	mock.recorder = &MockEngineMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockEngine) EXPECT() *MockEngineMockRecorder {
	return m.recorder
}

// Configure mocks base method.
func (m *MockEngine) Configure(config core.ServerConfig) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Configure", config)
	ret0, _ := ret[0].(error)
	return ret0
}

// Configure indicates an expected call of Configure.
func (mr *MockEngineMockRecorder) Configure(config interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Configure", reflect.TypeOf((*MockEngine)(nil).Configure), config)
}

// GetIterableKVStore mocks base method.
func (m *MockEngine) GetIterableKVStore(namespace, name string) (api.IterableKVStore, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetIterableKVStore", namespace, name)
	ret0, _ := ret[0].(api.IterableKVStore)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetIterableKVStore indicates an expected call of GetIterableKVStore.
func (mr *MockEngineMockRecorder) GetIterableKVStore(namespace, name interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetIterableKVStore", reflect.TypeOf((*MockEngine)(nil).GetIterableKVStore), namespace, name)
}

// GetKVStore mocks base method.
func (m *MockEngine) GetKVStore(namespace, name string) (api.KVStore, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetKVStore", namespace, name)
	ret0, _ := ret[0].(api.KVStore)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetKVStore indicates an expected call of GetKVStore.
func (mr *MockEngineMockRecorder) GetKVStore(namespace, name interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetKVStore", reflect.TypeOf((*MockEngine)(nil).GetKVStore), namespace, name)
}

// Shutdown mocks base method.
func (m *MockEngine) Shutdown() error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Shutdown")
	ret0, _ := ret[0].(error)
	return ret0
}

// Shutdown indicates an expected call of Shutdown.
func (mr *MockEngineMockRecorder) Shutdown() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Shutdown", reflect.TypeOf((*MockEngine)(nil).Shutdown))
}

// Start mocks base method.
func (m *MockEngine) Start() error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Start")
	ret0, _ := ret[0].(error)
	return ret0
}

// Start indicates an expected call of Start.
func (mr *MockEngineMockRecorder) Start() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Start", reflect.TypeOf((*MockEngine)(nil).Start))
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

// GetIterableKVStore mocks base method.
func (m *MockProvider) GetIterableKVStore(namespace, name string) (api.IterableKVStore, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetIterableKVStore", namespace, name)
	ret0, _ := ret[0].(api.IterableKVStore)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetIterableKVStore indicates an expected call of GetIterableKVStore.
func (mr *MockProviderMockRecorder) GetIterableKVStore(namespace, name interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetIterableKVStore", reflect.TypeOf((*MockProvider)(nil).GetIterableKVStore), namespace, name)
}

// GetKVStore mocks base method.
func (m *MockProvider) GetKVStore(namespace, name string) (api.KVStore, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetKVStore", namespace, name)
	ret0, _ := ret[0].(api.KVStore)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetKVStore indicates an expected call of GetKVStore.
func (mr *MockProviderMockRecorder) GetKVStore(namespace, name interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetKVStore", reflect.TypeOf((*MockProvider)(nil).GetKVStore), namespace, name)
}

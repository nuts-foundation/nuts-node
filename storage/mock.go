// Code generated by MockGen. DO NOT EDIT.
// Source: storage/interface.go
//
// Generated by this command:
//
//	mockgen -destination=storage/mock.go -package=storage -source=storage/interface.go
//

// Package storage is a generated GoMock package.
package storage

import (
	reflect "reflect"
	time "time"

	stoabs "github.com/nuts-foundation/go-stoabs"
	core "github.com/nuts-foundation/nuts-node/core"
	gomock "go.uber.org/mock/gomock"
	gorm "gorm.io/gorm"
)

// MockEngine is a mock of Engine interface.
type MockEngine struct {
	ctrl     *gomock.Controller
	recorder *MockEngineMockRecorder
	isgomock struct{}
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
func (mr *MockEngineMockRecorder) Configure(config any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Configure", reflect.TypeOf((*MockEngine)(nil).Configure), config)
}

// GetProvider mocks base method.
func (m *MockEngine) GetProvider(moduleName string) Provider {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetProvider", moduleName)
	ret0, _ := ret[0].(Provider)
	return ret0
}

// GetProvider indicates an expected call of GetProvider.
func (mr *MockEngineMockRecorder) GetProvider(moduleName any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetProvider", reflect.TypeOf((*MockEngine)(nil).GetProvider), moduleName)
}

// GetSQLDatabase mocks base method.
func (m *MockEngine) GetSQLDatabase() *gorm.DB {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetSQLDatabase")
	ret0, _ := ret[0].(*gorm.DB)
	return ret0
}

// GetSQLDatabase indicates an expected call of GetSQLDatabase.
func (mr *MockEngineMockRecorder) GetSQLDatabase() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetSQLDatabase", reflect.TypeOf((*MockEngine)(nil).GetSQLDatabase))
}

// GetSessionDatabase mocks base method.
func (m *MockEngine) GetSessionDatabase() SessionDatabase {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetSessionDatabase")
	ret0, _ := ret[0].(SessionDatabase)
	return ret0
}

// GetSessionDatabase indicates an expected call of GetSessionDatabase.
func (mr *MockEngineMockRecorder) GetSessionDatabase() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetSessionDatabase", reflect.TypeOf((*MockEngine)(nil).GetSessionDatabase))
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
	isgomock struct{}
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

// GetKVStore mocks base method.
func (m *MockProvider) GetKVStore(name string, class Class) (stoabs.KVStore, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetKVStore", name, class)
	ret0, _ := ret[0].(stoabs.KVStore)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetKVStore indicates an expected call of GetKVStore.
func (mr *MockProviderMockRecorder) GetKVStore(name, class any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetKVStore", reflect.TypeOf((*MockProvider)(nil).GetKVStore), name, class)
}

// Mockdatabase is a mock of database interface.
type Mockdatabase struct {
	ctrl     *gomock.Controller
	recorder *MockdatabaseMockRecorder
	isgomock struct{}
}

// MockdatabaseMockRecorder is the mock recorder for Mockdatabase.
type MockdatabaseMockRecorder struct {
	mock *Mockdatabase
}

// NewMockdatabase creates a new mock instance.
func NewMockdatabase(ctrl *gomock.Controller) *Mockdatabase {
	mock := &Mockdatabase{ctrl: ctrl}
	mock.recorder = &MockdatabaseMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *Mockdatabase) EXPECT() *MockdatabaseMockRecorder {
	return m.recorder
}

// close mocks base method.
func (m *Mockdatabase) close() {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "close")
}

// close indicates an expected call of close.
func (mr *MockdatabaseMockRecorder) close() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "close", reflect.TypeOf((*Mockdatabase)(nil).close))
}

// createStore mocks base method.
func (m *Mockdatabase) createStore(moduleName, storeName string) (stoabs.KVStore, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "createStore", moduleName, storeName)
	ret0, _ := ret[0].(stoabs.KVStore)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// createStore indicates an expected call of createStore.
func (mr *MockdatabaseMockRecorder) createStore(moduleName, storeName any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "createStore", reflect.TypeOf((*Mockdatabase)(nil).createStore), moduleName, storeName)
}

// getClass mocks base method.
func (m *Mockdatabase) getClass() Class {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "getClass")
	ret0, _ := ret[0].(Class)
	return ret0
}

// getClass indicates an expected call of getClass.
func (mr *MockdatabaseMockRecorder) getClass() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "getClass", reflect.TypeOf((*Mockdatabase)(nil).getClass))
}

// MockSessionDatabase is a mock of SessionDatabase interface.
type MockSessionDatabase struct {
	ctrl     *gomock.Controller
	recorder *MockSessionDatabaseMockRecorder
	isgomock struct{}
}

// MockSessionDatabaseMockRecorder is the mock recorder for MockSessionDatabase.
type MockSessionDatabaseMockRecorder struct {
	mock *MockSessionDatabase
}

// NewMockSessionDatabase creates a new mock instance.
func NewMockSessionDatabase(ctrl *gomock.Controller) *MockSessionDatabase {
	mock := &MockSessionDatabase{ctrl: ctrl}
	mock.recorder = &MockSessionDatabaseMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockSessionDatabase) EXPECT() *MockSessionDatabaseMockRecorder {
	return m.recorder
}

// Close mocks base method.
func (m *MockSessionDatabase) Close() {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "Close")
}

// Close indicates an expected call of Close.
func (mr *MockSessionDatabaseMockRecorder) Close() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Close", reflect.TypeOf((*MockSessionDatabase)(nil).Close))
}

// GetStore mocks base method.
func (m *MockSessionDatabase) GetStore(ttl time.Duration, keys ...string) SessionStore {
	m.ctrl.T.Helper()
	varargs := []any{ttl}
	for _, a := range keys {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "GetStore", varargs...)
	ret0, _ := ret[0].(SessionStore)
	return ret0
}

// GetStore indicates an expected call of GetStore.
func (mr *MockSessionDatabaseMockRecorder) GetStore(ttl any, keys ...any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]any{ttl}, keys...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetStore", reflect.TypeOf((*MockSessionDatabase)(nil).GetStore), varargs...)
}

// getFullKey mocks base method.
func (m *MockSessionDatabase) getFullKey(prefixes []string, key string) string {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "getFullKey", prefixes, key)
	ret0, _ := ret[0].(string)
	return ret0
}

// getFullKey indicates an expected call of getFullKey.
func (mr *MockSessionDatabaseMockRecorder) getFullKey(prefixes, key any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "getFullKey", reflect.TypeOf((*MockSessionDatabase)(nil).getFullKey), prefixes, key)
}

// MockSessionStore is a mock of SessionStore interface.
type MockSessionStore struct {
	ctrl     *gomock.Controller
	recorder *MockSessionStoreMockRecorder
	isgomock struct{}
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

// Delete mocks base method.
func (m *MockSessionStore) Delete(key string) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Delete", key)
	ret0, _ := ret[0].(error)
	return ret0
}

// Delete indicates an expected call of Delete.
func (mr *MockSessionStoreMockRecorder) Delete(key any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Delete", reflect.TypeOf((*MockSessionStore)(nil).Delete), key)
}

// Exists mocks base method.
func (m *MockSessionStore) Exists(key string) bool {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Exists", key)
	ret0, _ := ret[0].(bool)
	return ret0
}

// Exists indicates an expected call of Exists.
func (mr *MockSessionStoreMockRecorder) Exists(key any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Exists", reflect.TypeOf((*MockSessionStore)(nil).Exists), key)
}

// Get mocks base method.
func (m *MockSessionStore) Get(key string, target any) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Get", key, target)
	ret0, _ := ret[0].(error)
	return ret0
}

// Get indicates an expected call of Get.
func (mr *MockSessionStoreMockRecorder) Get(key, target any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Get", reflect.TypeOf((*MockSessionStore)(nil).Get), key, target)
}

// GetAndDelete mocks base method.
func (m *MockSessionStore) GetAndDelete(key string, target any) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetAndDelete", key, target)
	ret0, _ := ret[0].(error)
	return ret0
}

// GetAndDelete indicates an expected call of GetAndDelete.
func (mr *MockSessionStoreMockRecorder) GetAndDelete(key, target any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetAndDelete", reflect.TypeOf((*MockSessionStore)(nil).GetAndDelete), key, target)
}

// Put mocks base method.
func (m *MockSessionStore) Put(key string, value any, options ...SessionOption) error {
	m.ctrl.T.Helper()
	varargs := []any{key, value}
	for _, a := range options {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "Put", varargs...)
	ret0, _ := ret[0].(error)
	return ret0
}

// Put indicates an expected call of Put.
func (mr *MockSessionStoreMockRecorder) Put(key, value any, options ...any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]any{key, value}, options...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Put", reflect.TypeOf((*MockSessionStore)(nil).Put), varargs...)
}

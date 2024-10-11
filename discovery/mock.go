// Code generated by MockGen. DO NOT EDIT.
// Source: discovery/interface.go
//
// Generated by this command:
//
//	mockgen -destination=discovery/mock.go -package=discovery -source=discovery/interface.go
//

// Package discovery is a generated GoMock package.
package discovery

import (
	context "context"
	reflect "reflect"

	vc "github.com/nuts-foundation/go-did/vc"
	gomock "go.uber.org/mock/gomock"
)

// MockServer is a mock of Server interface.
type MockServer struct {
	ctrl     *gomock.Controller
	recorder *MockServerMockRecorder
}

// MockServerMockRecorder is the mock recorder for MockServer.
type MockServerMockRecorder struct {
	mock *MockServer
}

// NewMockServer creates a new mock instance.
func NewMockServer(ctrl *gomock.Controller) *MockServer {
	mock := &MockServer{ctrl: ctrl}
	mock.recorder = &MockServerMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockServer) EXPECT() *MockServerMockRecorder {
	return m.recorder
}

// Get mocks base method.
func (m *MockServer) Get(context context.Context, serviceID string, startAfter int) (map[string]vc.VerifiablePresentation, string, int, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Get", context, serviceID, startAfter)
	ret0, _ := ret[0].(map[string]vc.VerifiablePresentation)
	ret1, _ := ret[1].(string)
	ret2, _ := ret[2].(int)
	ret3, _ := ret[3].(error)
	return ret0, ret1, ret2, ret3
}

// Get indicates an expected call of Get.
func (mr *MockServerMockRecorder) Get(context, serviceID, startAfter any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Get", reflect.TypeOf((*MockServer)(nil).Get), context, serviceID, startAfter)
}

// Register mocks base method.
func (m *MockServer) Register(context context.Context, serviceID string, presentation vc.VerifiablePresentation) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Register", context, serviceID, presentation)
	ret0, _ := ret[0].(error)
	return ret0
}

// Register indicates an expected call of Register.
func (mr *MockServerMockRecorder) Register(context, serviceID, presentation any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Register", reflect.TypeOf((*MockServer)(nil).Register), context, serviceID, presentation)
}

// MockClient is a mock of Client interface.
type MockClient struct {
	ctrl     *gomock.Controller
	recorder *MockClientMockRecorder
}

// MockClientMockRecorder is the mock recorder for MockClient.
type MockClientMockRecorder struct {
	mock *MockClient
}

// NewMockClient creates a new mock instance.
func NewMockClient(ctrl *gomock.Controller) *MockClient {
	mock := &MockClient{ctrl: ctrl}
	mock.recorder = &MockClientMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockClient) EXPECT() *MockClientMockRecorder {
	return m.recorder
}

// ActivateServiceForSubject mocks base method.
func (m *MockClient) ActivateServiceForSubject(ctx context.Context, serviceID, subjectID string, parameters map[string]any) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ActivateServiceForSubject", ctx, serviceID, subjectID, parameters)
	ret0, _ := ret[0].(error)
	return ret0
}

// ActivateServiceForSubject indicates an expected call of ActivateServiceForSubject.
func (mr *MockClientMockRecorder) ActivateServiceForSubject(ctx, serviceID, subjectID, parameters any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ActivateServiceForSubject", reflect.TypeOf((*MockClient)(nil).ActivateServiceForSubject), ctx, serviceID, subjectID, parameters)
}

// DeactivateServiceForSubject mocks base method.
func (m *MockClient) DeactivateServiceForSubject(ctx context.Context, serviceID, subjectID string) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "DeactivateServiceForSubject", ctx, serviceID, subjectID)
	ret0, _ := ret[0].(error)
	return ret0
}

// DeactivateServiceForSubject indicates an expected call of DeactivateServiceForSubject.
func (mr *MockClientMockRecorder) DeactivateServiceForSubject(ctx, serviceID, subjectID any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DeactivateServiceForSubject", reflect.TypeOf((*MockClient)(nil).DeactivateServiceForSubject), ctx, serviceID, subjectID)
}

// GetServiceActivation mocks base method.
func (m *MockClient) GetServiceActivation(ctx context.Context, serviceID, subjectID string) (bool, []vc.VerifiablePresentation, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetServiceActivation", ctx, serviceID, subjectID)
	ret0, _ := ret[0].(bool)
	ret1, _ := ret[1].([]vc.VerifiablePresentation)
	ret2, _ := ret[2].(error)
	return ret0, ret1, ret2
}

// GetServiceActivation indicates an expected call of GetServiceActivation.
func (mr *MockClientMockRecorder) GetServiceActivation(ctx, serviceID, subjectID any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetServiceActivation", reflect.TypeOf((*MockClient)(nil).GetServiceActivation), ctx, serviceID, subjectID)
}

// Search mocks base method.
func (m *MockClient) Search(serviceID string, query map[string]string) ([]SearchResult, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Search", serviceID, query)
	ret0, _ := ret[0].([]SearchResult)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Search indicates an expected call of Search.
func (mr *MockClientMockRecorder) Search(serviceID, query any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Search", reflect.TypeOf((*MockClient)(nil).Search), serviceID, query)
}

// Services mocks base method.
func (m *MockClient) Services() []ServiceDefinition {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Services")
	ret0, _ := ret[0].([]ServiceDefinition)
	return ret0
}

// Services indicates an expected call of Services.
func (mr *MockClientMockRecorder) Services() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Services", reflect.TypeOf((*MockClient)(nil).Services))
}

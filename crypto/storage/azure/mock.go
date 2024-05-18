// Code generated by MockGen. DO NOT EDIT.
// Source: crypto/storage/azure/interface.go
//
// Generated by this command:
//
//	mockgen -destination=crypto/storage/azure/mock.go -package azure -source=crypto/storage/azure/interface.go
//

// Package azure is a generated GoMock package.
package azure

import (
	context "context"
	reflect "reflect"

	azkeys "github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
	gomock "go.uber.org/mock/gomock"
)

// MockkeyVaultClient is a mock of keyVaultClient interface.
type MockkeyVaultClient struct {
	ctrl     *gomock.Controller
	recorder *MockkeyVaultClientMockRecorder
}

// MockkeyVaultClientMockRecorder is the mock recorder for MockkeyVaultClient.
type MockkeyVaultClientMockRecorder struct {
	mock *MockkeyVaultClient
}

// NewMockkeyVaultClient creates a new mock instance.
func NewMockkeyVaultClient(ctrl *gomock.Controller) *MockkeyVaultClient {
	mock := &MockkeyVaultClient{ctrl: ctrl}
	mock.recorder = &MockkeyVaultClientMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockkeyVaultClient) EXPECT() *MockkeyVaultClientMockRecorder {
	return m.recorder
}

// CreateKey mocks base method.
func (m *MockkeyVaultClient) CreateKey(ctx context.Context, name string, parameters azkeys.CreateKeyParameters, options *azkeys.CreateKeyOptions) (azkeys.CreateKeyResponse, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "CreateKey", ctx, name, parameters, options)
	ret0, _ := ret[0].(azkeys.CreateKeyResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// CreateKey indicates an expected call of CreateKey.
func (mr *MockkeyVaultClientMockRecorder) CreateKey(ctx, name, parameters, options any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CreateKey", reflect.TypeOf((*MockkeyVaultClient)(nil).CreateKey), ctx, name, parameters, options)
}

// DeleteKey mocks base method.
func (m *MockkeyVaultClient) DeleteKey(ctx context.Context, name string, options *azkeys.DeleteKeyOptions) (azkeys.DeleteKeyResponse, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "DeleteKey", ctx, name, options)
	ret0, _ := ret[0].(azkeys.DeleteKeyResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// DeleteKey indicates an expected call of DeleteKey.
func (mr *MockkeyVaultClientMockRecorder) DeleteKey(ctx, name, options any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DeleteKey", reflect.TypeOf((*MockkeyVaultClient)(nil).DeleteKey), ctx, name, options)
}

// GetKey mocks base method.
func (m *MockkeyVaultClient) GetKey(ctx context.Context, name, version string, options *azkeys.GetKeyOptions) (azkeys.GetKeyResponse, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetKey", ctx, name, version, options)
	ret0, _ := ret[0].(azkeys.GetKeyResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetKey indicates an expected call of GetKey.
func (mr *MockkeyVaultClientMockRecorder) GetKey(ctx, name, version, options any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetKey", reflect.TypeOf((*MockkeyVaultClient)(nil).GetKey), ctx, name, version, options)
}

// Sign mocks base method.
func (m *MockkeyVaultClient) Sign(ctx context.Context, name, version string, parameters azkeys.SignParameters, options *azkeys.SignOptions) (azkeys.SignResponse, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Sign", ctx, name, version, parameters, options)
	ret0, _ := ret[0].(azkeys.SignResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Sign indicates an expected call of Sign.
func (mr *MockkeyVaultClientMockRecorder) Sign(ctx, name, version, parameters, options any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Sign", reflect.TypeOf((*MockkeyVaultClient)(nil).Sign), ctx, name, version, parameters, options)
}

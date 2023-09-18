// Code generated by MockGen. DO NOT EDIT.
// Source: didman/types.go
//
// Generated by this command:
//
//	mockgen -destination=didman/mock.go -package=didman -source=didman/types.go
//
// Package didman is a generated GoMock package.
package didman

import (
	context "context"
	url "net/url"
	reflect "reflect"

	ssi "github.com/nuts-foundation/go-did"
	did "github.com/nuts-foundation/go-did/did"
	gomock "go.uber.org/mock/gomock"
)

// MockDidman is a mock of Didman interface.
type MockDidman struct {
	ctrl     *gomock.Controller
	recorder *MockDidmanMockRecorder
}

// MockDidmanMockRecorder is the mock recorder for MockDidman.
type MockDidmanMockRecorder struct {
	mock *MockDidman
}

// NewMockDidman creates a new mock instance.
func NewMockDidman(ctrl *gomock.Controller) *MockDidman {
	mock := &MockDidman{ctrl: ctrl}
	mock.recorder = &MockDidmanMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockDidman) EXPECT() *MockDidmanMockRecorder {
	return m.recorder
}

// AddCompoundService mocks base method.
func (m *MockDidman) AddCompoundService(ctx context.Context, id did.DID, serviceType string, endpoints map[string]ssi.URI) (*did.Service, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "AddCompoundService", ctx, id, serviceType, endpoints)
	ret0, _ := ret[0].(*did.Service)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// AddCompoundService indicates an expected call of AddCompoundService.
func (mr *MockDidmanMockRecorder) AddCompoundService(ctx, id, serviceType, endpoints any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "AddCompoundService", reflect.TypeOf((*MockDidman)(nil).AddCompoundService), ctx, id, serviceType, endpoints)
}

// AddEndpoint mocks base method.
func (m *MockDidman) AddEndpoint(ctx context.Context, id did.DID, serviceType string, endpoint url.URL) (*did.Service, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "AddEndpoint", ctx, id, serviceType, endpoint)
	ret0, _ := ret[0].(*did.Service)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// AddEndpoint indicates an expected call of AddEndpoint.
func (mr *MockDidmanMockRecorder) AddEndpoint(ctx, id, serviceType, endpoint any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "AddEndpoint", reflect.TypeOf((*MockDidman)(nil).AddEndpoint), ctx, id, serviceType, endpoint)
}

// DeleteEndpointsByType mocks base method.
func (m *MockDidman) DeleteEndpointsByType(ctx context.Context, id did.DID, serviceType string) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "DeleteEndpointsByType", ctx, id, serviceType)
	ret0, _ := ret[0].(error)
	return ret0
}

// DeleteEndpointsByType indicates an expected call of DeleteEndpointsByType.
func (mr *MockDidmanMockRecorder) DeleteEndpointsByType(ctx, id, serviceType any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DeleteEndpointsByType", reflect.TypeOf((*MockDidman)(nil).DeleteEndpointsByType), ctx, id, serviceType)
}

// DeleteService mocks base method.
func (m *MockDidman) DeleteService(ctx context.Context, id ssi.URI) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "DeleteService", ctx, id)
	ret0, _ := ret[0].(error)
	return ret0
}

// DeleteService indicates an expected call of DeleteService.
func (mr *MockDidmanMockRecorder) DeleteService(ctx, id any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DeleteService", reflect.TypeOf((*MockDidman)(nil).DeleteService), ctx, id)
}

// GetCompoundServiceEndpoint mocks base method.
func (m *MockDidman) GetCompoundServiceEndpoint(id did.DID, compoundServiceType, endpointType string, resolveReferences bool) (string, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetCompoundServiceEndpoint", id, compoundServiceType, endpointType, resolveReferences)
	ret0, _ := ret[0].(string)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetCompoundServiceEndpoint indicates an expected call of GetCompoundServiceEndpoint.
func (mr *MockDidmanMockRecorder) GetCompoundServiceEndpoint(id, compoundServiceType, endpointType, resolveReferences any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetCompoundServiceEndpoint", reflect.TypeOf((*MockDidman)(nil).GetCompoundServiceEndpoint), id, compoundServiceType, endpointType, resolveReferences)
}

// GetCompoundServices mocks base method.
func (m *MockDidman) GetCompoundServices(id did.DID) ([]did.Service, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetCompoundServices", id)
	ret0, _ := ret[0].([]did.Service)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetCompoundServices indicates an expected call of GetCompoundServices.
func (mr *MockDidmanMockRecorder) GetCompoundServices(id any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetCompoundServices", reflect.TypeOf((*MockDidman)(nil).GetCompoundServices), id)
}

// GetContactInformation mocks base method.
func (m *MockDidman) GetContactInformation(id did.DID) (*ContactInformation, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetContactInformation", id)
	ret0, _ := ret[0].(*ContactInformation)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetContactInformation indicates an expected call of GetContactInformation.
func (mr *MockDidmanMockRecorder) GetContactInformation(id any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetContactInformation", reflect.TypeOf((*MockDidman)(nil).GetContactInformation), id)
}

// SearchOrganizations mocks base method.
func (m *MockDidman) SearchOrganizations(ctx context.Context, query string, didServiceType *string) ([]OrganizationSearchResult, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "SearchOrganizations", ctx, query, didServiceType)
	ret0, _ := ret[0].([]OrganizationSearchResult)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// SearchOrganizations indicates an expected call of SearchOrganizations.
func (mr *MockDidmanMockRecorder) SearchOrganizations(ctx, query, didServiceType any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SearchOrganizations", reflect.TypeOf((*MockDidman)(nil).SearchOrganizations), ctx, query, didServiceType)
}

// UpdateCompoundService mocks base method.
func (m *MockDidman) UpdateCompoundService(ctx context.Context, id did.DID, serviceType string, endpoints map[string]ssi.URI) (*did.Service, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "UpdateCompoundService", ctx, id, serviceType, endpoints)
	ret0, _ := ret[0].(*did.Service)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// UpdateCompoundService indicates an expected call of UpdateCompoundService.
func (mr *MockDidmanMockRecorder) UpdateCompoundService(ctx, id, serviceType, endpoints any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "UpdateCompoundService", reflect.TypeOf((*MockDidman)(nil).UpdateCompoundService), ctx, id, serviceType, endpoints)
}

// UpdateContactInformation mocks base method.
func (m *MockDidman) UpdateContactInformation(ctx context.Context, id did.DID, information ContactInformation) (*ContactInformation, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "UpdateContactInformation", ctx, id, information)
	ret0, _ := ret[0].(*ContactInformation)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// UpdateContactInformation indicates an expected call of UpdateContactInformation.
func (mr *MockDidmanMockRecorder) UpdateContactInformation(ctx, id, information any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "UpdateContactInformation", reflect.TypeOf((*MockDidman)(nil).UpdateContactInformation), ctx, id, information)
}

// UpdateEndpoint mocks base method.
func (m *MockDidman) UpdateEndpoint(ctx context.Context, id did.DID, serviceType string, endpoint url.URL) (*did.Service, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "UpdateEndpoint", ctx, id, serviceType, endpoint)
	ret0, _ := ret[0].(*did.Service)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// UpdateEndpoint indicates an expected call of UpdateEndpoint.
func (mr *MockDidmanMockRecorder) UpdateEndpoint(ctx, id, serviceType, endpoint any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "UpdateEndpoint", reflect.TypeOf((*MockDidman)(nil).UpdateEndpoint), ctx, id, serviceType, endpoint)
}

// MockCompoundServiceResolver is a mock of CompoundServiceResolver interface.
type MockCompoundServiceResolver struct {
	ctrl     *gomock.Controller
	recorder *MockCompoundServiceResolverMockRecorder
}

// MockCompoundServiceResolverMockRecorder is the mock recorder for MockCompoundServiceResolver.
type MockCompoundServiceResolverMockRecorder struct {
	mock *MockCompoundServiceResolver
}

// NewMockCompoundServiceResolver creates a new mock instance.
func NewMockCompoundServiceResolver(ctrl *gomock.Controller) *MockCompoundServiceResolver {
	mock := &MockCompoundServiceResolver{ctrl: ctrl}
	mock.recorder = &MockCompoundServiceResolverMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockCompoundServiceResolver) EXPECT() *MockCompoundServiceResolverMockRecorder {
	return m.recorder
}

// GetCompoundServiceEndpoint mocks base method.
func (m *MockCompoundServiceResolver) GetCompoundServiceEndpoint(id did.DID, compoundServiceType, endpointType string, resolveReferences bool) (string, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetCompoundServiceEndpoint", id, compoundServiceType, endpointType, resolveReferences)
	ret0, _ := ret[0].(string)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetCompoundServiceEndpoint indicates an expected call of GetCompoundServiceEndpoint.
func (mr *MockCompoundServiceResolverMockRecorder) GetCompoundServiceEndpoint(id, compoundServiceType, endpointType, resolveReferences any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetCompoundServiceEndpoint", reflect.TypeOf((*MockCompoundServiceResolver)(nil).GetCompoundServiceEndpoint), id, compoundServiceType, endpointType, resolveReferences)
}

// GetCompoundServices mocks base method.
func (m *MockCompoundServiceResolver) GetCompoundServices(id did.DID) ([]did.Service, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetCompoundServices", id)
	ret0, _ := ret[0].([]did.Service)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetCompoundServices indicates an expected call of GetCompoundServices.
func (mr *MockCompoundServiceResolverMockRecorder) GetCompoundServices(id any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetCompoundServices", reflect.TypeOf((*MockCompoundServiceResolver)(nil).GetCompoundServices), id)
}

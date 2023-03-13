// Code generated by protoc-gen-go-grpc. DO NOT EDIT.
// versions:
// - protoc-gen-go-grpc v1.2.0
// - protoc             v3.21.12
// source: transport/grpc/testprotocol.proto

package grpc

import (
	context "context"

	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
)

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
// Requires gRPC-Go v1.32.0 or later.
const _ = grpc.SupportPackageIsVersion7

// TestClient is the client API for Test service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type TestClient interface {
	DoStuff(ctx context.Context, opts ...grpc.CallOption) (Test_DoStuffClient, error)
}

type testClient struct {
	cc grpc.ClientConnInterface
}

func NewTestClient(cc grpc.ClientConnInterface) TestClient {
	return &testClient{cc}
}

func (c *testClient) DoStuff(ctx context.Context, opts ...grpc.CallOption) (Test_DoStuffClient, error) {
	stream, err := c.cc.NewStream(ctx, &Test_ServiceDesc.Streams[0], "/grpc.Test/DoStuff", opts...)
	if err != nil {
		return nil, err
	}
	x := &testDoStuffClient{stream}
	return x, nil
}

type Test_DoStuffClient interface {
	Send(*TestMessage) error
	Recv() (*TestMessage, error)
	grpc.ClientStream
}

type testDoStuffClient struct {
	grpc.ClientStream
}

func (x *testDoStuffClient) Send(m *TestMessage) error {
	return x.ClientStream.SendMsg(m)
}

func (x *testDoStuffClient) Recv() (*TestMessage, error) {
	m := new(TestMessage)
	if err := x.ClientStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

// TestServer is the server API for Test service.
// All implementations should embed UnimplementedTestServer
// for forward compatibility
type TestServer interface {
	DoStuff(Test_DoStuffServer) error
}

// UnimplementedTestServer should be embedded to have forward compatible implementations.
type UnimplementedTestServer struct {
}

func (UnimplementedTestServer) DoStuff(Test_DoStuffServer) error {
	return status.Errorf(codes.Unimplemented, "method DoStuff not implemented")
}

// UnsafeTestServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to TestServer will
// result in compilation errors.
type UnsafeTestServer interface {
	mustEmbedUnimplementedTestServer()
}

func RegisterTestServer(s grpc.ServiceRegistrar, srv TestServer) {
	s.RegisterService(&Test_ServiceDesc, srv)
}

func _Test_DoStuff_Handler(srv interface{}, stream grpc.ServerStream) error {
	return srv.(TestServer).DoStuff(&testDoStuffServer{stream})
}

type Test_DoStuffServer interface {
	Send(*TestMessage) error
	Recv() (*TestMessage, error)
	grpc.ServerStream
}

type testDoStuffServer struct {
	grpc.ServerStream
}

func (x *testDoStuffServer) Send(m *TestMessage) error {
	return x.ServerStream.SendMsg(m)
}

func (x *testDoStuffServer) Recv() (*TestMessage, error) {
	m := new(TestMessage)
	if err := x.ServerStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

// Test_ServiceDesc is the grpc.ServiceDesc for Test service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var Test_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "grpc.Test",
	HandlerType: (*TestServer)(nil),
	Methods:     []grpc.MethodDesc{},
	Streams: []grpc.StreamDesc{
		{
			StreamName:    "DoStuff",
			Handler:       _Test_DoStuff_Handler,
			ServerStreams: true,
			ClientStreams: true,
		},
	},
	Metadata: "transport/grpc/testprotocol.proto",
}

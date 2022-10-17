// Code generated by protoc-gen-go-grpc. DO NOT EDIT.
// versions:
// - protoc-gen-go-grpc v1.2.0
// - protoc             v3.21.7
// source: transport/v2/protocol.proto

package v2

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

// ProtocolClient is the client API for Protocol service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type ProtocolClient interface {
	Stream(ctx context.Context, opts ...grpc.CallOption) (Protocol_StreamClient, error)
}

type protocolClient struct {
	cc grpc.ClientConnInterface
}

func NewProtocolClient(cc grpc.ClientConnInterface) ProtocolClient {
	return &protocolClient{cc}
}

func (c *protocolClient) Stream(ctx context.Context, opts ...grpc.CallOption) (Protocol_StreamClient, error) {
	stream, err := c.cc.NewStream(ctx, &Protocol_ServiceDesc.Streams[0], "/v2.Protocol/Stream", opts...)
	if err != nil {
		return nil, err
	}
	x := &protocolStreamClient{stream}
	return x, nil
}

type Protocol_StreamClient interface {
	Send(*Envelope) error
	Recv() (*Envelope, error)
	grpc.ClientStream
}

type protocolStreamClient struct {
	grpc.ClientStream
}

func (x *protocolStreamClient) Send(m *Envelope) error {
	return x.ClientStream.SendMsg(m)
}

func (x *protocolStreamClient) Recv() (*Envelope, error) {
	m := new(Envelope)
	if err := x.ClientStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

// ProtocolServer is the server API for Protocol service.
// All implementations should embed UnimplementedProtocolServer
// for forward compatibility
type ProtocolServer interface {
	Stream(Protocol_StreamServer) error
}

// UnimplementedProtocolServer should be embedded to have forward compatible implementations.
type UnimplementedProtocolServer struct {
}

func (UnimplementedProtocolServer) Stream(Protocol_StreamServer) error {
	return status.Errorf(codes.Unimplemented, "method Stream not implemented")
}

// UnsafeProtocolServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to ProtocolServer will
// result in compilation errors.
type UnsafeProtocolServer interface {
	mustEmbedUnimplementedProtocolServer()
}

func RegisterProtocolServer(s grpc.ServiceRegistrar, srv ProtocolServer) {
	s.RegisterService(&Protocol_ServiceDesc, srv)
}

func _Protocol_Stream_Handler(srv interface{}, stream grpc.ServerStream) error {
	return srv.(ProtocolServer).Stream(&protocolStreamServer{stream})
}

type Protocol_StreamServer interface {
	Send(*Envelope) error
	Recv() (*Envelope, error)
	grpc.ServerStream
}

type protocolStreamServer struct {
	grpc.ServerStream
}

func (x *protocolStreamServer) Send(m *Envelope) error {
	return x.ServerStream.SendMsg(m)
}

func (x *protocolStreamServer) Recv() (*Envelope, error) {
	m := new(Envelope)
	if err := x.ServerStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

// Protocol_ServiceDesc is the grpc.ServiceDesc for Protocol service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var Protocol_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "v2.Protocol",
	HandlerType: (*ProtocolServer)(nil),
	Methods:     []grpc.MethodDesc{},
	Streams: []grpc.StreamDesc{
		{
			StreamName:    "Stream",
			Handler:       _Protocol_Stream_Handler,
			ServerStreams: true,
			ClientStreams: true,
		},
	},
	Metadata: "transport/v2/protocol.proto",
}

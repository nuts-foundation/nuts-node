package grpc

// ReceiveMessages is a helper function which receives messages from the given StreamReceiver.
// The supplied callbacks are invoked when a message is received or an error occurs. The function blocks until an error occurs.
func ReceiveMessages(receiver StreamReceiver, messageCreator func() interface{}, onMessage func(msg interface{}), onError func(err error)) {
	for {
		msg := messageCreator()
		err := receiver.RecvMsg(msg)
		if err != nil {
			onError(err)
			return
		}
		onMessage(msg)
	}
}

// StreamReceiver defines a function for receiving a message through a gRPC stream. It is implemented by both grpc.ServerStream and grpc.ClientStream.
type StreamReceiver interface {
	RecvMsg(m interface{}) error
}

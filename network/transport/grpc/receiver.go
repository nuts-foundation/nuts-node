package grpc

func ReceiveMessages(receiver StreamReceiver, messageCreator func() interface{}, onMessage func(msg interface{}), onError func(err error)) {
	for {
		msg := messageCreator()
		err := receiver.RecvMsg(msg)
		if err != nil {
			onError(err)
			return
		} else {
			onMessage(msg)
		}
	}
}

type StreamReceiver interface {
	RecvMsg(m interface{}) error
}

package grpc

func ReceiveMessages(receiver StreamReceiver, messageCreator func() interface{}, cb func(msg interface{}, err error)) {
	go func() {
		for {
			msg := messageCreator()
			err := receiver.RecvMsg(msg)
			if err != nil {
				cb(nil, err)
			} else {
				cb(msg, nil)
			}
		}
	}()
}

type StreamReceiver interface {
	RecvMsg(m interface{}) error
}

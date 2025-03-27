package json

import "github.com/sugawarayuuta/sonnet"

type Unmarshaler = sonnet.Unmarshaler

type Marshaler = sonnet.Marshaler

var NewEncoder = sonnet.NewEncoder
var NewDecoder = sonnet.NewDecoder
var MarshalIndent = sonnet.MarshalIndent

type RawMessage = sonnet.RawMessage

func Unmarshal(data []byte, v interface{}) error {
	return sonnet.Unmarshal(data, v)
}

func Marshal(v interface{}) ([]byte, error) {
	return sonnet.Marshal(v)
}

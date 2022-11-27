// Package stream provides the event-stream mechanism.
package stream

import (
	"errors"
	"io"
	"strings"
)

//go:generate colf -b .. -f -s "4 * 1024 * 1024" go

// SigPart returns the signature part of the JWS, which uniquely identifies the
// transaction with a base64 sequence.
func (e *Event) SigPart() string {
	return e.JWS[strings.LastIndexByte(e.JWS, '.')+1:]
}

// SizeMax is the upper limit for serial byte-sizes on event-stream records.
var SizeMax = &ColferSizeMax

// ErrSizeMax signals a SizeMax breach.
var ErrSizeMax = errors.New("stream: record serial too big")

// Appender feeds an event-stream (log).
type Appender interface {
	io.Closer

	// All errors from AppendEvent other than ErrMax are fatal.
	// That is, such error return requires a Close as follow-up.
	AppendEvent(Event) error
}

// NoData makes read operation non-blocking.
var NoData = errors.New("stream: reached the end")

// Iterator provides an event-stream (log).
type Iterator interface {
	io.Closer

	// All errors from NextEvent other than NoData are fatal.
	// That is, such error return requires a Close as follow-up.
	NextEvent() (Event, error)
}

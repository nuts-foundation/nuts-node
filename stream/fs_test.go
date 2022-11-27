package stream_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/nuts-foundation/nuts-node/stream"
	"github.com/nuts-foundation/nuts-node/stream/streamtest"
)

func TestNoDataRecover(t *testing.T) {
	const testJWS = "foo.bar"
	appender, iterator := streamtest.Pipe(t)

	_, err := iterator.NextEvent()
	if !errors.Is(err, stream.NoData) {
		t.Fatalf("next event on an empty stream got error %q, want stream.NoData", err)
	}

	err = appender.AppendEvent(stream.Event{JWS: testJWS})
	if err != nil {
		t.Fatal(err)
	}

	got, err := iterator.NextEvent()
	if err != nil {
		t.Fatal(err)
	}
	if got.JWS != testJWS {
		t.Errorf("got JWS %q, want %q", got.JWS, testJWS)
	}
}

func TestSizeMax(t *testing.T) {
	appender, iterator := streamtest.Pipe(t)

	err := appender.AppendEvent(stream.Event{JWS: strings.Repeat("A", *stream.SizeMax)})
	if !errors.Is(err, stream.ErrSizeMax) {
		t.Fatalf("got error %q, want ErrSizeMax", err)
	}

	_, err = iterator.NextEvent()
	switch err {
	case nil:
		t.Error("received an event after size rejection, want NoData")
	case stream.NoData:
		break // OK
	default:
		t.Errorf("received error %q, want NoData", err)
	}
}

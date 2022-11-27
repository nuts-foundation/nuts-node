package stream

import (
	"errors"
	"fmt"
	"io"
	"os"
)

type appendFatal struct{ error }

// Close implements io.Closer.
func (appendFatal) Close() error { return nil }

// AppendEvent implements Appender.
func (f appendFatal) AppendEvent(Event) error { return f.error }

type appendFile struct{ *os.File }

// AppendEvent implements Appender.
func (f appendFile) AppendEvent(e Event) error {
	buf, err := e.MarshalBinary()
	if err != nil {
		var smax ColferMax
		if errors.As(err, &smax) {
			err = ErrSizeMax
		}
		return err
	}
	_, err = f.File.Write(buf)
	return err
}

// OpenAppender connects to a filesystem persistence.
func OpenAppender(path string) Appender {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND|os.O_SYNC, 0o644)
	if err != nil {
		return appendFatal{err}
	}
	return appendFile{f}
}

type iterateFatal struct{ error }

func (iterateFatal) Close() error { return nil }

func (f iterateFatal) NextEvent() (Event, error) { return Event{}, f.error }

type iterateFile struct {
	*os.File
	buf    []byte
	offset int
}

// Close implements io.Closer.
func (f *iterateFile) Close() error {
	return f.File.Close()
}

// NextEvent implements Iterator.
func (f *iterateFile) NextEvent() (Event, error) {
	for {
		var e Event
		n, err := e.Unmarshal(f.buf[f.offset:])
		switch {
		case err == nil:
			f.offset += n
			return e, nil

		case errors.Is(err, io.EOF):
			switch {
			case f.offset >= len(f.buf):
				// reset with no pending data
				f.buf = f.buf[:0]
				f.offset = 0
			case len(f.buf) >= cap(f.buf):
				// move remainder to buffer begin
				f.buf = f.buf[:copy(f.buf, f.buf[f.offset:])]
				f.offset = 0
			}

			n, err := f.File.Read(f.buf[len(f.buf):cap(f.buf)])
			f.buf = f.buf[:len(f.buf)+n]
			switch {
			case err == nil:
				continue
			case errors.Is(err, io.EOF):
				return Event{}, NoData
			default:
				return Event{}, err
			}

		default:
			return Event{}, fmt.Errorf("%s: record corrupt: %w", f.File.Name(), err)
		}
	}
}

// OpenIterator connects to a filesystem persistence.
func OpenIterator(path string) Iterator {
	f, err := os.Open(path)
	if err != nil {
		return iterateFatal{err}
	}

	return &iterateFile{
		File: f,
		buf:  make([]byte, 0, ColferSizeMax),
	}
}

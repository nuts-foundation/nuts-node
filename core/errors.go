package core

import (
	"fmt"
	"github.com/go-errors/errors"
)

type wrappedError struct {
	err   error
	cause error
}

func (w wrappedError) Error() string {
	// Use Sprintf to avoid nil dereferences, when someone accidentally passes a nil err or cause.
	return fmt.Sprintf("%s", w.err) + ": " + fmt.Sprintf("%s", w.cause)
}

func (w wrappedError) Is(other error) bool {
	return errors.Is(w.err, other)
}

func (w wrappedError) Unwrap() error {
	return w.cause
}

// WrapError returns an error that wraps a cause. In contrary to fmt.Errorf, errors.Is can be used on both the outer error and cause.
func WrapError(err error, cause error) error {
	return wrappedError{
		err:   err,
		cause: cause,
	}
}

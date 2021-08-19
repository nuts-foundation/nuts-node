package wraperr

import (
	"errors"
	"fmt"
)

type wrappedError struct {
	err   error
	cause error
}

// Error returns a string which contains both err and cause's error messages.
func (w wrappedError) Error() string {
	return fmt.Sprintf("%s: %s", w.err, w.cause)
}

// Is checks whether err or cause Is() the given target err.
func (w wrappedError) Is(target error) bool {
	return errors.Is(w.err, target) || errors.Is(w.cause, target)
}

// Wrap wraps err and cause, meaning the returned error is both.
func Wrap(err, cause error) error {
	return &wrappedError{
		err:   err,
		cause: cause,
	}
}

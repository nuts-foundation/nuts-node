package wraperr

import (
	"errors"
	"fmt"
)

type wrappedError struct {
	err error
	cause error
}

func (w wrappedError) Error() string {
	return fmt.Sprintf("%s: %s", w.err, w.cause)
}

func (w wrappedError) Is(target error) bool {
	return errors.Is(w.err, target) || errors.Is(w.cause, target)
}

func Wrap(err, cause error) error {
	return &wrappedError{
		err: err,
		cause: cause,
	}
}

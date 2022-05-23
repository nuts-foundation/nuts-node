/*
 * Copyright (C) 2022 Nuts community
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 *
 */

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

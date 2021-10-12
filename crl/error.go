package crl

import (
	"fmt"
	"strings"
)

// SyncError is returned by the CRL database when synchronization fails
type SyncError struct {
	errors []error
}

// Errors returns all errors that happened when synchronizing all CRLs
func (err *SyncError) Errors() []error {
	return err.errors
}

func (err *SyncError) Error() string {
	var summary []string

	for _, inner := range err.errors {
		summary = append(summary, inner.Error())
	}

	return fmt.Sprintf("synchronization failed: %s", strings.Join(summary, ", "))
}

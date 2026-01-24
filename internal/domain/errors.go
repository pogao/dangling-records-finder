package domain

import (
	"errors"
	"fmt"
)

var (
	// ErrSourceNotConfigured is returned when a required source is not configured.
	ErrSourceNotConfigured = errors.New("source not configured")

	// ErrInvalidZoneFile is returned when a zone file cannot be parsed.
	ErrInvalidZoneFile = errors.New("invalid zone file")

	// ErrResolutionFailed is returned when DNS resolution fails.
	ErrResolutionFailed = errors.New("DNS resolution failed")

	// ErrCheckFailed is returned when a resource availability check fails.
	ErrCheckFailed = errors.New("resource check failed")

	// ErrTimeout is returned when an operation times out.
	ErrTimeout = errors.New("operation timed out")

	// ErrRateLimited is returned when rate limiting is encountered.
	ErrRateLimited = errors.New("rate limited")

	// ErrNoRecords is returned when no records are found.
	ErrNoRecords = errors.New("no records found")

	// ErrInvalidConfig is returned when configuration is invalid.
	ErrInvalidConfig = errors.New("invalid configuration")
)

// SourceError wraps an error from a source with additional context.
type SourceError struct {
	Source string
	Op     string
	Err    error
}

func (e *SourceError) Error() string {
	return fmt.Sprintf("source %s: %s: %v", e.Source, e.Op, e.Err)
}

func (e *SourceError) Unwrap() error {
	return e.Err
}

// NewSourceError creates a new SourceError.
func NewSourceError(source, op string, err error) *SourceError {
	return &SourceError{
		Source: source,
		Op:     op,
		Err:    err,
	}
}

// CheckError wraps an error from a checker with additional context.
type CheckError struct {
	Checker string
	Target  string
	Err     error
}

func (e *CheckError) Error() string {
	return fmt.Sprintf("checker %s: target %s: %v", e.Checker, e.Target, e.Err)
}

func (e *CheckError) Unwrap() error {
	return e.Err
}

// NewCheckError creates a new CheckError.
func NewCheckError(checker, target string, err error) *CheckError {
	return &CheckError{
		Checker: checker,
		Target:  target,
		Err:     err,
	}
}

// ResolutionError wraps a DNS resolution error with additional context.
type ResolutionError struct {
	Name       string
	RecordType string
	Err        error
}

func (e *ResolutionError) Error() string {
	return fmt.Sprintf("resolving %s %s: %v", e.RecordType, e.Name, e.Err)
}

func (e *ResolutionError) Unwrap() error {
	return e.Err
}

// NewResolutionError creates a new ResolutionError.
func NewResolutionError(name, recordType string, err error) *ResolutionError {
	return &ResolutionError{
		Name:       name,
		RecordType: recordType,
		Err:        err,
	}
}

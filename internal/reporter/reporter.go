// Package reporter provides output generation for findings.
package reporter

import (
	"context"
	"fmt"
	"io"

	"github.com/pogao/dangling-records-finder/internal/domain"
)

// Reporter outputs findings in a specific format.
type Reporter interface {
	// Report writes findings to the given writer.
	Report(ctx context.Context, findings []domain.Finding, w io.Writer) error

	// Format returns the output format name.
	Format() string
}

// Config contains common reporter configuration.
type Config struct {
	// IncludeEvidence includes detailed evidence in the output.
	IncludeEvidence bool

	// Verbose enables verbose output.
	Verbose bool
}

// NewReporter creates a reporter for the given format.
func NewReporter(format string, config Config) (Reporter, error) {
	switch format {
	case "json":
		return NewJSONReporter(config), nil
	case "csv":
		return NewCSVReporter(config), nil
	case "console", "text", "":
		return NewConsoleReporter(config), nil
	default:
		return nil, fmt.Errorf("unknown output format: %s", format)
	}
}

// SupportedFormats returns a list of supported output formats.
func SupportedFormats() []string {
	return []string{"json", "csv", "console"}
}

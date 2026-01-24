// Package source provides interfaces and implementations for fetching DNS records.
package source

import (
	"context"

	"github.com/pogao/dangling-records-finder/internal/domain"
)

// Source fetches DNS records from a provider or file.
type Source interface {
	// FetchRecords retrieves all DNS zones and their records.
	FetchRecords(ctx context.Context) ([]*domain.Zone, error)

	// Name returns the source identifier.
	Name() string
}

// Config contains common configuration for sources.
type Config struct {
	// Verbose enables debug logging.
	Verbose bool
}

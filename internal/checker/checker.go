// Package checker provides cloud resource availability checking.
package checker

import (
	"context"
	"net/http"
	"sync"
	"time"

	"github.com/pogao/dangling-records-finder/internal/domain"
	"github.com/pogao/dangling-records-finder/internal/resolver"
)

// Checker validates if a cloud resource is claimable.
type Checker interface {
	// Name returns the checker identifier.
	Name() string

	// MatchesTarget returns true if this checker handles the given target.
	MatchesTarget(target string) bool

	// CheckAvailability checks if the target resource is claimable.
	CheckAvailability(ctx context.Context, target string) (domain.ResourceStatus, error)
}

// Registry manages multiple checkers.
type Registry struct {
	checkers []Checker
	mu       sync.RWMutex
}

// NewRegistry creates a new checker registry with all default checkers.
func NewRegistry(httpClient *http.Client, resolver *resolver.DNSResolver) *Registry {
	if httpClient == nil {
		httpClient = &http.Client{
			Timeout: 10 * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				// Don't follow redirects automatically for detection
				return http.ErrUseLastResponse
			},
		}
	}

	r := &Registry{}
	r.Register(NewAWSS3Checker(httpClient))
	r.Register(NewAWSCloudFrontChecker(httpClient, resolver))
	r.Register(NewAWSBeanstalkChecker(resolver))
	r.Register(NewAzureBlobChecker(httpClient))
	r.Register(NewAzureCDNChecker(httpClient, resolver))
	r.Register(NewGitHubPagesChecker(httpClient))
	r.Register(NewHerokuChecker(httpClient))

	return r
}

// Register adds a checker to the registry.
func (r *Registry) Register(c Checker) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.checkers = append(r.checkers, c)
}

// FindChecker returns the first checker that matches the target.
func (r *Registry) FindChecker(target string) Checker {
	r.mu.RLock()
	defer r.mu.RUnlock()

	for _, c := range r.checkers {
		if c.MatchesTarget(target) {
			return c
		}
	}
	return nil
}

// AllCheckers returns all registered checkers.
func (r *Registry) AllCheckers() []Checker {
	r.mu.RLock()
	defer r.mu.RUnlock()

	result := make([]Checker, len(r.checkers))
	copy(result, r.checkers)
	return result
}

// CheckerNames returns the names of all registered checkers.
func (r *Registry) CheckerNames() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	names := make([]string, len(r.checkers))
	for i, c := range r.checkers {
		names[i] = c.Name()
	}
	return names
}

// BaseChecker provides common functionality for checkers.
type BaseChecker struct {
	name       string
	httpClient *http.Client
	resolver   *resolver.DNSResolver
}

// Name returns the checker identifier.
func (b *BaseChecker) Name() string {
	return b.name
}

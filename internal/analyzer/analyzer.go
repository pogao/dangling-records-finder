// Package analyzer provides the core analysis engine for detecting dangling DNS records.
package analyzer

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/pogao/dangling-records-finder/internal/checker"
	"github.com/pogao/dangling-records-finder/internal/domain"
	"github.com/pogao/dangling-records-finder/internal/resolver"
)

// Analyzer orchestrates the detection of dangling DNS records.
type Analyzer interface {
	// Analyze checks all zones for dangling DNS records.
	Analyze(ctx context.Context, zones []*domain.Zone) ([]domain.Finding, error)
}

// Config contains analyzer configuration.
type Config struct {
	// Concurrency is the number of parallel checks.
	Concurrency int

	// Timeout is the timeout for each check.
	Timeout time.Duration

	// Verbose enables debug logging.
	Verbose bool

	// EnabledProviders limits which providers to check (empty = all).
	EnabledProviders []string

	// RateLimit is the minimum duration between checks to the same provider.
	RateLimit time.Duration
}

// DefaultConfig returns the default analyzer configuration.
func DefaultConfig() Config {
	return Config{
		Concurrency: 10,
		Timeout:     10 * time.Second,
		Verbose:     false,
		RateLimit:   100 * time.Millisecond,
	}
}

// DefaultAnalyzer implements the Analyzer interface.
type DefaultAnalyzer struct {
	registry *checker.Registry
	resolver *resolver.DNSResolver
	config   Config
}

// New creates a new analyzer with the given configuration.
func New(registry *checker.Registry, resolver *resolver.DNSResolver, config Config) *DefaultAnalyzer {
	if config.Concurrency <= 0 {
		config.Concurrency = DefaultConfig().Concurrency
	}
	if config.Timeout <= 0 {
		config.Timeout = DefaultConfig().Timeout
	}

	return &DefaultAnalyzer{
		registry: registry,
		resolver: resolver,
		config:   config,
	}
}

// checkTask represents a single record to check.
type checkTask struct {
	record *domain.Record
	target string
}

// Analyze checks all zones for dangling DNS records.
func (a *DefaultAnalyzer) Analyze(ctx context.Context, zones []*domain.Zone) ([]domain.Finding, error) {
	// Collect all candidate records
	var tasks []checkTask
	for _, zone := range zones {
		for _, record := range zone.TakeoverCandidates() {
			if record.Type == domain.RecordTypeCNAME {
				// For CNAME records, check the target
				target := record.Target()
				if target != "" && a.shouldCheck(target) {
					tasks = append(tasks, checkTask{record: record, target: target})
				}
			}
			// For A/AAAA records, we could check if they point to cloud IPs
			// but that's more complex and requires IP range databases
		}
	}

	if len(tasks) == 0 {
		return nil, nil
	}

	if a.config.Verbose {
		log.Printf("Analyzing %d candidate records across %d zones", len(tasks), len(zones))
	}

	// Process tasks concurrently
	findings := a.processTasksConcurrently(ctx, tasks)

	return findings, nil
}

func (a *DefaultAnalyzer) shouldCheck(target string) bool {
	// Check if any registered checker handles this target
	c := a.registry.FindChecker(target)
	if c == nil {
		return false
	}

	// If providers are limited, check if this checker is enabled
	if len(a.config.EnabledProviders) > 0 {
		enabled := false
		for _, p := range a.config.EnabledProviders {
			if c.Name() == p {
				enabled = true
				break
			}
		}
		if !enabled {
			return false
		}
	}

	return true
}

func (a *DefaultAnalyzer) processTasksConcurrently(ctx context.Context, tasks []checkTask) []domain.Finding {
	var (
		findings []domain.Finding
		mu       sync.Mutex
		wg       sync.WaitGroup
	)

	// Create a semaphore for concurrency control
	sem := make(chan struct{}, a.config.Concurrency)

	for _, task := range tasks {
		select {
		case <-ctx.Done():
			break
		case sem <- struct{}{}:
		}

		wg.Add(1)
		go func(t checkTask) {
			defer wg.Done()
			defer func() { <-sem }()

			finding := a.checkRecord(ctx, t)
			if finding != nil {
				mu.Lock()
				findings = append(findings, *finding)
				mu.Unlock()
			}
		}(task)
	}

	wg.Wait()
	return findings
}

func (a *DefaultAnalyzer) checkRecord(ctx context.Context, task checkTask) *domain.Finding {
	// Apply timeout
	ctx, cancel := context.WithTimeout(ctx, a.config.Timeout)
	defer cancel()

	// Find the appropriate checker
	c := a.registry.FindChecker(task.target)
	if c == nil {
		return nil
	}

	if a.config.Verbose {
		log.Printf("Checking %s -> %s with %s", task.record.Name, task.target, c.Name())
	}

	// Check availability
	status, err := c.CheckAvailability(ctx, task.target)
	if err != nil {
		if a.config.Verbose {
			log.Printf("Error checking %s: %v", task.target, err)
		}
		// Create an unknown finding if there was an error
		finding := domain.NewUnknownFinding(task.record, task.target, c.Name(), extractResourceType(c.Name()), err.Error())
		return finding
	}

	switch status {
	case domain.ResourceStatusClaimable:
		finding := domain.NewClaimableFinding(task.record, task.target, c.Name(), extractResourceType(c.Name()))
		finding.Evidence["checker"] = c.Name()
		finding.Evidence["status"] = string(status)
		finding.Description = fmt.Sprintf("The DNS record %s points to %s which does not exist and can be claimed by an attacker. This is a critical subdomain takeover vulnerability.",
			task.record.Name, task.target)
		finding.Remediation = fmt.Sprintf("Either remove the DNS record %s or recreate the %s resource '%s' to prevent subdomain takeover.",
			task.record.Name, c.Name(), task.target)
		return finding

	case domain.ResourceStatusUnknown:
		finding := domain.NewUnknownFinding(task.record, task.target, c.Name(), extractResourceType(c.Name()), "status could not be determined")
		return finding

	default:
		// ResourceStatusExists or ResourceStatusError - not a finding
		return nil
	}
}

func extractResourceType(checkerName string) string {
	switch checkerName {
	case "aws-s3":
		return "S3 Bucket"
	case "aws-cloudfront":
		return "CloudFront Distribution"
	case "aws-beanstalk":
		return "Elastic Beanstalk Environment"
	case "azure-blob":
		return "Azure Blob Storage"
	case "azure-cdn":
		return "Azure CDN Endpoint"
	case "github-pages":
		return "GitHub Pages Site"
	case "heroku":
		return "Heroku App"
	default:
		return "Cloud Resource"
	}
}

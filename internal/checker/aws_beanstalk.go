package checker

import (
	"context"
	"regexp"
	"strings"

	"github.com/pogao/dangling-records-finder/internal/domain"
	"github.com/pogao/dangling-records-finder/internal/resolver"
)

// AWSBeanstalkChecker checks for claimable AWS Elastic Beanstalk environments.
type AWSBeanstalkChecker struct {
	BaseChecker
}

// Elastic Beanstalk patterns
var beanstalkPatterns = []*regexp.Regexp{
	// Standard: app-name.region.elasticbeanstalk.com
	regexp.MustCompile(`^[a-z0-9-]+\.[a-z]+-[a-z]+-[0-9]+\.elasticbeanstalk\.com$`),
	// Also: app-name.elasticbeanstalk.com
	regexp.MustCompile(`^[a-z0-9-]+\.elasticbeanstalk\.com$`),
}

// NewAWSBeanstalkChecker creates a new Elastic Beanstalk checker.
func NewAWSBeanstalkChecker(resolver *resolver.DNSResolver) *AWSBeanstalkChecker {
	return &AWSBeanstalkChecker{
		BaseChecker: BaseChecker{
			name:     "aws-beanstalk",
			resolver: resolver,
		},
	}
}

// MatchesTarget returns true if the target looks like an Elastic Beanstalk environment.
func (c *AWSBeanstalkChecker) MatchesTarget(target string) bool {
	target = strings.ToLower(target)
	for _, pattern := range beanstalkPatterns {
		if pattern.MatchString(target) {
			return true
		}
	}
	return false
}

// CheckAvailability checks if an Elastic Beanstalk environment is claimable.
func (c *AWSBeanstalkChecker) CheckAvailability(ctx context.Context, target string) (domain.ResourceStatus, error) {
	target = strings.ToLower(target)

	if c.resolver == nil {
		return domain.ResourceStatusUnknown, domain.NewCheckError(c.name, target, domain.ErrResolutionFailed)
	}

	// Check DNS resolution - NXDOMAIN indicates the environment doesn't exist
	nxdomain, err := c.resolver.IsNXDOMAIN(ctx, target)
	if err != nil {
		return domain.ResourceStatusUnknown, nil
	}

	if nxdomain {
		return domain.ResourceStatusClaimable, nil
	}

	return domain.ResourceStatusExists, nil
}

// ExtractEnvironmentName extracts the environment name from a Beanstalk target.
func (c *AWSBeanstalkChecker) ExtractEnvironmentName(target string) string {
	target = strings.ToLower(target)
	// Remove .elasticbeanstalk.com suffix
	name := strings.TrimSuffix(target, ".elasticbeanstalk.com")
	// Remove region if present
	parts := strings.Split(name, ".")
	if len(parts) > 1 {
		return parts[0]
	}
	return name
}

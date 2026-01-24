package checker

import (
	"context"
	"io"
	"net/http"
	"regexp"
	"strings"

	"github.com/pogao/dangling-records-finder/internal/domain"
	"github.com/pogao/dangling-records-finder/internal/resolver"
)

// AWSCloudFrontChecker checks for claimable AWS CloudFront distributions.
type AWSCloudFrontChecker struct {
	BaseChecker
}

// CloudFront pattern: d123456abcdef8.cloudfront.net
var cloudFrontPattern = regexp.MustCompile(`^[a-z0-9]+\.cloudfront\.net$`)

// NewAWSCloudFrontChecker creates a new CloudFront checker.
func NewAWSCloudFrontChecker(httpClient *http.Client, resolver *resolver.DNSResolver) *AWSCloudFrontChecker {
	return &AWSCloudFrontChecker{
		BaseChecker: BaseChecker{
			name:       "aws-cloudfront",
			httpClient: httpClient,
			resolver:   resolver,
		},
	}
}

// MatchesTarget returns true if the target looks like a CloudFront distribution.
func (c *AWSCloudFrontChecker) MatchesTarget(target string) bool {
	return cloudFrontPattern.MatchString(strings.ToLower(target))
}

// CheckAvailability checks if a CloudFront distribution is claimable.
func (c *AWSCloudFrontChecker) CheckAvailability(ctx context.Context, target string) (domain.ResourceStatus, error) {
	target = strings.ToLower(target)

	// First, check DNS resolution
	if c.resolver != nil {
		nxdomain, err := c.resolver.IsNXDOMAIN(ctx, target)
		if err != nil {
			// Continue to HTTP check on DNS error
		} else if nxdomain {
			// NXDOMAIN means the distribution doesn't exist
			return domain.ResourceStatusClaimable, nil
		}
	}

	// HTTP check for more details
	url := "https://" + target + "/"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return domain.ResourceStatusError, domain.NewCheckError(c.name, target, err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		// Connection errors might indicate the distribution doesn't exist
		if strings.Contains(err.Error(), "no such host") {
			return domain.ResourceStatusClaimable, nil
		}
		return domain.ResourceStatusUnknown, nil
	}
	defer resp.Body.Close()

	// Read response body
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return domain.ResourceStatusUnknown, nil
	}
	bodyStr := string(body)

	// CloudFront returns specific errors for missing distributions
	// "Bad Request" or specific CloudFront error codes
	if resp.StatusCode == 400 || resp.StatusCode == 403 {
		// Check for CloudFront-specific error messages
		if strings.Contains(bodyStr, "ERROR") || strings.Contains(bodyStr, "CloudFront") {
			// The distribution might exist but be misconfigured
			if strings.Contains(bodyStr, "The request could not be satisfied") {
				return domain.ResourceStatusExists, nil
			}
		}
	}

	// 502/503 often indicates the origin is unreachable but distribution exists
	if resp.StatusCode == 502 || resp.StatusCode == 503 {
		return domain.ResourceStatusExists, nil
	}

	// Successful response means it exists
	if resp.StatusCode >= 200 && resp.StatusCode < 400 {
		return domain.ResourceStatusExists, nil
	}

	return domain.ResourceStatusUnknown, nil
}

// ExtractDistributionID extracts the distribution ID from a CloudFront target.
func (c *AWSCloudFrontChecker) ExtractDistributionID(target string) string {
	target = strings.ToLower(target)
	return strings.TrimSuffix(target, ".cloudfront.net")
}

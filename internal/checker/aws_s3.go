package checker

import (
	"context"
	"io"
	"net/http"
	"regexp"
	"strings"

	"github.com/pogao/dangling-records-finder/internal/domain"
)

// AWSS3Checker checks for claimable AWS S3 buckets.
type AWSS3Checker struct {
	BaseChecker
}

// S3 bucket patterns
var s3Patterns = []*regexp.Regexp{
	// Virtual-hosted style: bucket.s3.amazonaws.com
	regexp.MustCompile(`^([a-z0-9][a-z0-9.-]*[a-z0-9])\.s3\.amazonaws\.com$`),
	// Virtual-hosted style with region: bucket.s3-us-west-2.amazonaws.com
	regexp.MustCompile(`^([a-z0-9][a-z0-9.-]*[a-z0-9])\.s3-[a-z0-9-]+\.amazonaws\.com$`),
	// Virtual-hosted style with region (dot notation): bucket.s3.us-west-2.amazonaws.com
	regexp.MustCompile(`^([a-z0-9][a-z0-9.-]*[a-z0-9])\.s3\.[a-z0-9-]+\.amazonaws\.com$`),
	// Path-style: s3.amazonaws.com/bucket
	regexp.MustCompile(`^s3\.amazonaws\.com$`),
	// Path-style with region: s3-us-west-2.amazonaws.com/bucket
	regexp.MustCompile(`^s3-[a-z0-9-]+\.amazonaws\.com$`),
	// Website hosting style: bucket.s3-website-us-east-1.amazonaws.com
	regexp.MustCompile(`^([a-z0-9][a-z0-9.-]*[a-z0-9])\.s3-website-[a-z0-9-]+\.amazonaws\.com$`),
	// Website hosting style (dot notation): bucket.s3-website.us-east-1.amazonaws.com
	regexp.MustCompile(`^([a-z0-9][a-z0-9.-]*[a-z0-9])\.s3-website\.[a-z0-9-]+\.amazonaws\.com$`),
}

// NewAWSS3Checker creates a new S3 bucket checker.
func NewAWSS3Checker(httpClient *http.Client) *AWSS3Checker {
	return &AWSS3Checker{
		BaseChecker: BaseChecker{
			name:       "aws-s3",
			httpClient: httpClient,
		},
	}
}

// MatchesTarget returns true if the target looks like an S3 bucket.
func (c *AWSS3Checker) MatchesTarget(target string) bool {
	target = strings.ToLower(target)
	for _, pattern := range s3Patterns {
		if pattern.MatchString(target) {
			return true
		}
	}
	return false
}

// CheckAvailability checks if an S3 bucket is claimable.
func (c *AWSS3Checker) CheckAvailability(ctx context.Context, target string) (domain.ResourceStatus, error) {
	target = strings.ToLower(target)
	url := "http://" + target + "/"

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return domain.ResourceStatusError, domain.NewCheckError(c.name, target, err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		// Network errors might indicate the bucket doesn't exist
		return domain.ResourceStatusUnknown, nil
	}
	defer resp.Body.Close()

	// Read response body for error detection
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return domain.ResourceStatusUnknown, nil
	}
	bodyStr := string(body)

	// Check for "NoSuchBucket" error - this means the bucket doesn't exist and can be claimed
	if strings.Contains(bodyStr, "NoSuchBucket") {
		return domain.ResourceStatusClaimable, nil
	}

	// Check for "NoSuchWebsiteConfiguration" - bucket exists but no website config
	if strings.Contains(bodyStr, "NoSuchWebsiteConfiguration") {
		return domain.ResourceStatusExists, nil
	}

	// 404 with specific S3 errors could indicate claimable
	if resp.StatusCode == 404 && strings.Contains(bodyStr, "<Error>") {
		if strings.Contains(bodyStr, "NoSuchBucket") {
			return domain.ResourceStatusClaimable, nil
		}
	}

	// 403 means the bucket exists but we don't have access
	if resp.StatusCode == 403 {
		return domain.ResourceStatusExists, nil
	}

	// 200 means the bucket exists and is accessible
	if resp.StatusCode == 200 {
		return domain.ResourceStatusExists, nil
	}

	return domain.ResourceStatusUnknown, nil
}

// ExtractBucketName extracts the bucket name from an S3 target.
func (c *AWSS3Checker) ExtractBucketName(target string) string {
	target = strings.ToLower(target)
	for _, pattern := range s3Patterns {
		matches := pattern.FindStringSubmatch(target)
		if len(matches) >= 2 {
			return matches[1]
		}
	}
	return ""
}

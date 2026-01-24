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

// AzureCDNChecker checks for claimable Azure CDN endpoints.
type AzureCDNChecker struct {
	BaseChecker
}

// Azure CDN patterns
var azureCDNPatterns = []*regexp.Regexp{
	// Standard CDN: endpoint.azureedge.net
	regexp.MustCompile(`^[a-z0-9][a-z0-9-]*[a-z0-9]\.azureedge\.net$`),
	// Azure Front Door: endpoint.azurefd.net
	regexp.MustCompile(`^[a-z0-9][a-z0-9-]*[a-z0-9]\.azurefd\.net$`),
	// Azure Traffic Manager: profile.trafficmanager.net
	regexp.MustCompile(`^[a-z0-9][a-z0-9-]*[a-z0-9]\.trafficmanager\.net$`),
}

// NewAzureCDNChecker creates a new Azure CDN checker.
func NewAzureCDNChecker(httpClient *http.Client, resolver *resolver.DNSResolver) *AzureCDNChecker {
	return &AzureCDNChecker{
		BaseChecker: BaseChecker{
			name:       "azure-cdn",
			httpClient: httpClient,
			resolver:   resolver,
		},
	}
}

// MatchesTarget returns true if the target looks like an Azure CDN endpoint.
func (c *AzureCDNChecker) MatchesTarget(target string) bool {
	target = strings.ToLower(target)
	for _, pattern := range azureCDNPatterns {
		if pattern.MatchString(target) {
			return true
		}
	}
	return false
}

// CheckAvailability checks if an Azure CDN endpoint is claimable.
func (c *AzureCDNChecker) CheckAvailability(ctx context.Context, target string) (domain.ResourceStatus, error) {
	target = strings.ToLower(target)

	// First, check DNS resolution
	if c.resolver != nil {
		nxdomain, err := c.resolver.IsNXDOMAIN(ctx, target)
		if err != nil {
			// Continue to HTTP check on DNS error
		} else if nxdomain {
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
		// Connection errors might indicate the endpoint doesn't exist
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

	// Check for specific Azure error messages
	if strings.Contains(bodyStr, "The resource you are looking for has been removed") {
		return domain.ResourceStatusClaimable, nil
	}

	if strings.Contains(bodyStr, "endpoint not found") {
		return domain.ResourceStatusClaimable, nil
	}

	// 404 might indicate endpoint doesn't exist
	if resp.StatusCode == 404 {
		// Check response headers for Azure-specific indicators
		if resp.Header.Get("X-MSEdge-Ref") == "" {
			// Might not be a valid Azure CDN response
			return domain.ResourceStatusClaimable, nil
		}
	}

	// 502/503 often indicates origin issues but endpoint exists
	if resp.StatusCode == 502 || resp.StatusCode == 503 {
		return domain.ResourceStatusExists, nil
	}

	// Successful response means it exists
	if resp.StatusCode >= 200 && resp.StatusCode < 400 {
		return domain.ResourceStatusExists, nil
	}

	return domain.ResourceStatusUnknown, nil
}

// ExtractEndpointName extracts the endpoint name from an Azure CDN target.
func (c *AzureCDNChecker) ExtractEndpointName(target string) string {
	target = strings.ToLower(target)
	for _, suffix := range []string{".azureedge.net", ".azurefd.net", ".trafficmanager.net"} {
		if strings.HasSuffix(target, suffix) {
			return strings.TrimSuffix(target, suffix)
		}
	}
	return ""
}

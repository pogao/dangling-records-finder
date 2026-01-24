package checker

import (
	"context"
	"io"
	"net/http"
	"regexp"
	"strings"

	"github.com/pogao/dangling-records-finder/internal/domain"
)

// GitHubPagesChecker checks for claimable GitHub Pages sites.
type GitHubPagesChecker struct {
	BaseChecker
}

// GitHub Pages pattern: username.github.io or organization.github.io
var githubPagesPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]*[a-z0-9]\.github\.io$`)

// NewGitHubPagesChecker creates a new GitHub Pages checker.
func NewGitHubPagesChecker(httpClient *http.Client) *GitHubPagesChecker {
	return &GitHubPagesChecker{
		BaseChecker: BaseChecker{
			name:       "github-pages",
			httpClient: httpClient,
		},
	}
}

// MatchesTarget returns true if the target looks like a GitHub Pages site.
func (c *GitHubPagesChecker) MatchesTarget(target string) bool {
	return githubPagesPattern.MatchString(strings.ToLower(target))
}

// CheckAvailability checks if a GitHub Pages site is claimable.
func (c *GitHubPagesChecker) CheckAvailability(ctx context.Context, target string) (domain.ResourceStatus, error) {
	target = strings.ToLower(target)
	url := "https://" + target + "/"

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return domain.ResourceStatusError, domain.NewCheckError(c.name, target, err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		// Connection errors might indicate the site doesn't exist
		if strings.Contains(err.Error(), "no such host") {
			return domain.ResourceStatusClaimable, nil
		}
		return domain.ResourceStatusUnknown, nil
	}
	defer resp.Body.Close()

	// Read response body
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8192))
	if err != nil {
		return domain.ResourceStatusUnknown, nil
	}
	bodyStr := string(body)

	// Check for the specific GitHub Pages "no site" message
	// This is the key indicator that an attacker can claim the subdomain
	if resp.StatusCode == 404 {
		if strings.Contains(bodyStr, "There isn't a GitHub Pages site here") {
			return domain.ResourceStatusClaimable, nil
		}
		// Other 404 messages might indicate the user/org exists but no Pages site
		if strings.Contains(bodyStr, "Site not found") {
			return domain.ResourceStatusClaimable, nil
		}
	}

	// Check for GitHub's custom domain verification page
	if strings.Contains(bodyStr, "For root URLs") && strings.Contains(bodyStr, "GitHub Pages") {
		return domain.ResourceStatusClaimable, nil
	}

	// Successful response means the site exists
	if resp.StatusCode >= 200 && resp.StatusCode < 400 {
		return domain.ResourceStatusExists, nil
	}

	return domain.ResourceStatusUnknown, nil
}

// ExtractUsername extracts the username/organization from a GitHub Pages target.
func (c *GitHubPagesChecker) ExtractUsername(target string) string {
	target = strings.ToLower(target)
	return strings.TrimSuffix(target, ".github.io")
}

// IsOrganization checks if the target might be an organization (heuristic).
func (c *GitHubPagesChecker) IsOrganization(target string) bool {
	// Can't really tell without API access, but organizations often have
	// longer or hyphenated names
	username := c.ExtractUsername(target)
	return len(username) > 15 || strings.Contains(username, "-")
}

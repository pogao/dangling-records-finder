package checker

import (
	"context"
	"io"
	"net/http"
	"regexp"
	"strings"

	"github.com/pogao/dangling-records-finder/internal/domain"
)

// HerokuChecker checks for claimable Heroku apps.
type HerokuChecker struct {
	BaseChecker
}

// Heroku app pattern: app-name.herokuapp.com
var herokuPattern = regexp.MustCompile(`^[a-z][a-z0-9-]*\.herokuapp\.com$`)

// NewHerokuChecker creates a new Heroku checker.
func NewHerokuChecker(httpClient *http.Client) *HerokuChecker {
	return &HerokuChecker{
		BaseChecker: BaseChecker{
			name:       "heroku",
			httpClient: httpClient,
		},
	}
}

// MatchesTarget returns true if the target looks like a Heroku app.
func (c *HerokuChecker) MatchesTarget(target string) bool {
	return herokuPattern.MatchString(strings.ToLower(target))
}

// CheckAvailability checks if a Heroku app is claimable.
func (c *HerokuChecker) CheckAvailability(ctx context.Context, target string) (domain.ResourceStatus, error) {
	target = strings.ToLower(target)
	url := "https://" + target + "/"

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return domain.ResourceStatusError, domain.NewCheckError(c.name, target, err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		// Connection errors might indicate the app doesn't exist
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

	// Check for Heroku's "no such app" error page
	// The exact message has changed over time, check for common patterns
	noAppIndicators := []string{
		"No such app",
		"There is no app configured at that hostname",
		"Heroku | No such app",
		"no app was found",
	}

	for _, indicator := range noAppIndicators {
		if strings.Contains(bodyStr, indicator) {
			return domain.ResourceStatusClaimable, nil
		}
	}

	// Check for Heroku error codes
	if resp.StatusCode == 404 {
		// Check if it's a Heroku 404 (app doesn't exist) vs app returning 404
		if strings.Contains(bodyStr, "heroku") || strings.Contains(bodyStr, "Heroku") {
			return domain.ResourceStatusClaimable, nil
		}
	}

	// Heroku maintenance page might indicate app exists but is down
	if strings.Contains(bodyStr, "Application Error") && strings.Contains(bodyStr, "Heroku") {
		return domain.ResourceStatusExists, nil
	}

	// Successful response means the app exists
	if resp.StatusCode >= 200 && resp.StatusCode < 400 {
		return domain.ResourceStatusExists, nil
	}

	// 503 might indicate the app is sleeping but exists
	if resp.StatusCode == 503 {
		return domain.ResourceStatusExists, nil
	}

	return domain.ResourceStatusUnknown, nil
}

// ExtractAppName extracts the app name from a Heroku target.
func (c *HerokuChecker) ExtractAppName(target string) string {
	target = strings.ToLower(target)
	return strings.TrimSuffix(target, ".herokuapp.com")
}

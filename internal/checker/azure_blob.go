package checker

import (
	"context"
	"io"
	"net/http"
	"regexp"
	"strings"

	"github.com/pogao/dangling-records-finder/internal/domain"
)

// AzureBlobChecker checks for claimable Azure Blob Storage accounts.
type AzureBlobChecker struct {
	BaseChecker
}

// Azure Blob Storage pattern: storageaccount.blob.core.windows.net
var azureBlobPattern = regexp.MustCompile(`^[a-z0-9]{3,24}\.blob\.core\.windows\.net$`)

// NewAzureBlobChecker creates a new Azure Blob Storage checker.
func NewAzureBlobChecker(httpClient *http.Client) *AzureBlobChecker {
	return &AzureBlobChecker{
		BaseChecker: BaseChecker{
			name:       "azure-blob",
			httpClient: httpClient,
		},
	}
}

// MatchesTarget returns true if the target looks like an Azure Blob Storage account.
func (c *AzureBlobChecker) MatchesTarget(target string) bool {
	return azureBlobPattern.MatchString(strings.ToLower(target))
}

// CheckAvailability checks if an Azure Blob Storage account is claimable.
func (c *AzureBlobChecker) CheckAvailability(ctx context.Context, target string) (domain.ResourceStatus, error) {
	target = strings.ToLower(target)
	url := "https://" + target + "/?comp=list"

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return domain.ResourceStatusError, domain.NewCheckError(c.name, target, err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		// Connection errors might indicate the account doesn't exist
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

	// Check for specific Azure error codes
	// AccountNotFound means the storage account doesn't exist and can be claimed
	if strings.Contains(bodyStr, "AccountNotFound") {
		return domain.ResourceStatusClaimable, nil
	}

	// ResourceNotFound might also indicate the account doesn't exist
	if strings.Contains(bodyStr, "ResourceNotFound") {
		return domain.ResourceStatusClaimable, nil
	}

	// DNS resolution failed
	if strings.Contains(bodyStr, "BlobNotFound") {
		return domain.ResourceStatusExists, nil
	}

	// 404 without specific error might indicate account doesn't exist
	if resp.StatusCode == 404 {
		// Need to differentiate between "account doesn't exist" and "container/blob doesn't exist"
		if strings.Contains(bodyStr, "AccountNotFound") || strings.Contains(bodyStr, "InvalidResourceName") {
			return domain.ResourceStatusClaimable, nil
		}
		return domain.ResourceStatusUnknown, nil
	}

	// 403 means the account exists but we don't have access
	if resp.StatusCode == 403 {
		return domain.ResourceStatusExists, nil
	}

	// 400 might indicate account exists with different configuration
	if resp.StatusCode == 400 {
		if strings.Contains(bodyStr, "InvalidQueryParameterValue") {
			return domain.ResourceStatusExists, nil
		}
	}

	// Successful response means it exists
	if resp.StatusCode >= 200 && resp.StatusCode < 400 {
		return domain.ResourceStatusExists, nil
	}

	return domain.ResourceStatusUnknown, nil
}

// ExtractAccountName extracts the storage account name from an Azure Blob target.
func (c *AzureBlobChecker) ExtractAccountName(target string) string {
	target = strings.ToLower(target)
	return strings.TrimSuffix(target, ".blob.core.windows.net")
}

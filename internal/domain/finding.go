package domain

import "time"

// Severity represents the severity level of a finding.
type Severity string

const (
	SeverityCritical Severity = "CRITICAL"
	SeverityHigh     Severity = "HIGH"
	SeverityMedium   Severity = "MEDIUM"
	SeverityLow      Severity = "LOW"
	SeverityInfo     Severity = "INFO"
)

// ResourceStatus represents the status of a cloud resource.
type ResourceStatus string

const (
	// ResourceStatusClaimable means the resource can be claimed by an attacker.
	ResourceStatusClaimable ResourceStatus = "CLAIMABLE"

	// ResourceStatusExists means the resource exists and is not claimable.
	ResourceStatusExists ResourceStatus = "EXISTS"

	// ResourceStatusUnknown means the status could not be determined.
	ResourceStatusUnknown ResourceStatus = "UNKNOWN"

	// ResourceStatusError means an error occurred during checking.
	ResourceStatusError ResourceStatus = "ERROR"
)

// Finding represents a security finding from the analysis.
type Finding struct {
	// ID is a unique identifier for this finding.
	ID string

	// Record is the DNS record associated with this finding.
	Record *Record

	// Target is the cloud resource or hostname being pointed to.
	Target string

	// Provider identifies the cloud provider (aws, azure, github, heroku, etc.).
	Provider string

	// ResourceType describes the type of resource (s3, cloudfront, blob, etc.).
	ResourceType string

	// Status indicates whether the resource is claimable.
	Status ResourceStatus

	// Severity indicates the risk level.
	Severity Severity

	// Title is a short description of the finding.
	Title string

	// Description provides detailed information about the finding.
	Description string

	// Remediation provides guidance on how to fix the issue.
	Remediation string

	// Evidence contains proof/details of the finding.
	Evidence map[string]string

	// DetectedAt is when this finding was discovered.
	DetectedAt time.Time
}

// IsCritical returns true if the finding represents a critical vulnerability.
func (f *Finding) IsCritical() bool {
	return f.Status == ResourceStatusClaimable
}

// NewClaimableFinding creates a new finding for a claimable resource.
func NewClaimableFinding(record *Record, target, provider, resourceType string) *Finding {
	return &Finding{
		ID:           generateFindingID(record, target),
		Record:       record,
		Target:       target,
		Provider:     provider,
		ResourceType: resourceType,
		Status:       ResourceStatusClaimable,
		Severity:     SeverityCritical,
		Title:        "Dangling DNS Record - Subdomain Takeover Possible",
		Description:  "This DNS record points to a cloud resource that does not exist and can be claimed by an attacker.",
		Remediation:  "Remove the DNS record or recreate the cloud resource to prevent subdomain takeover.",
		Evidence:     make(map[string]string),
		DetectedAt:   time.Now().UTC(),
	}
}

// NewUnknownFinding creates a new finding for a resource with unknown status.
func NewUnknownFinding(record *Record, target, provider, resourceType, reason string) *Finding {
	return &Finding{
		ID:           generateFindingID(record, target),
		Record:       record,
		Target:       target,
		Provider:     provider,
		ResourceType: resourceType,
		Status:       ResourceStatusUnknown,
		Severity:     SeverityMedium,
		Title:        "DNS Record Status Unknown",
		Description:  "Could not determine if this DNS record points to a claimable resource: " + reason,
		Remediation:  "Manually verify the resource exists and is properly configured.",
		Evidence:     make(map[string]string),
		DetectedAt:   time.Now().UTC(),
	}
}

func generateFindingID(record *Record, target string) string {
	return record.Name + "_" + target
}

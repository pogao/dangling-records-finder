package reporter

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/pogao/dangling-records-finder/internal/domain"
)

func createTestFindings() []domain.Finding {
	return []domain.Finding{
		{
			ID: "test-finding-1",
			Record: &domain.Record{
				Name:   "cdn.example.com.",
				Type:   domain.RecordTypeCNAME,
				Zone:   "example.com.",
				Values: []string{"mybucket.s3.amazonaws.com"},
			},
			Target:       "mybucket.s3.amazonaws.com",
			Provider:     "aws-s3",
			ResourceType: "S3 Bucket",
			Status:       domain.ResourceStatusClaimable,
			Severity:     domain.SeverityCritical,
			Title:        "Dangling DNS Record - Subdomain Takeover Possible",
			Description:  "The S3 bucket does not exist and can be claimed.",
			Remediation:  "Remove the DNS record or recreate the bucket.",
			Evidence:     map[string]string{"checker": "aws-s3", "status": "CLAIMABLE"},
			DetectedAt:   time.Now().UTC(),
		},
		{
			ID: "test-finding-2",
			Record: &domain.Record{
				Name:   "docs.example.com.",
				Type:   domain.RecordTypeCNAME,
				Zone:   "example.com.",
				Values: []string{"myorg.github.io"},
			},
			Target:       "myorg.github.io",
			Provider:     "github-pages",
			ResourceType: "GitHub Pages Site",
			Status:       domain.ResourceStatusUnknown,
			Severity:     domain.SeverityMedium,
			Title:        "DNS Record Status Unknown",
			Description:  "Could not determine status.",
			Remediation:  "Manually verify.",
			Evidence:     nil,
			DetectedAt:   time.Now().UTC(),
		},
	}
}

func TestNewReporter(t *testing.T) {
	tests := []struct {
		format  string
		wantFmt string
		wantErr bool
	}{
		{"json", "json", false},
		{"csv", "csv", false},
		{"console", "console", false},
		{"text", "console", false},
		{"", "console", false},
		{"unknown", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.format, func(t *testing.T) {
			r, err := NewReporter(tt.format, Config{})
			if (err != nil) != tt.wantErr {
				t.Errorf("NewReporter(%q) error = %v, wantErr %v", tt.format, err, tt.wantErr)
				return
			}
			if err == nil && r.Format() != tt.wantFmt {
				t.Errorf("NewReporter(%q).Format() = %q, want %q", tt.format, r.Format(), tt.wantFmt)
			}
		})
	}
}

func TestJSONReporter_Report(t *testing.T) {
	reporter := NewJSONReporter(Config{IncludeEvidence: true})
	findings := createTestFindings()

	var buf bytes.Buffer
	err := reporter.Report(context.Background(), findings, &buf)
	if err != nil {
		t.Fatalf("Report failed: %v", err)
	}

	// Verify it's valid JSON
	var output JSONOutput
	if err := json.Unmarshal(buf.Bytes(), &output); err != nil {
		t.Fatalf("Invalid JSON output: %v", err)
	}

	// Verify summary
	if output.Summary.Total != 2 {
		t.Errorf("Expected total 2, got %d", output.Summary.Total)
	}
	if output.Summary.Critical != 1 {
		t.Errorf("Expected 1 critical, got %d", output.Summary.Critical)
	}
	if output.Summary.Medium != 1 {
		t.Errorf("Expected 1 medium, got %d", output.Summary.Medium)
	}

	// Verify findings
	if len(output.Findings) != 2 {
		t.Errorf("Expected 2 findings, got %d", len(output.Findings))
	}

	// Verify evidence is included
	if output.Findings[0].Evidence == nil {
		t.Error("Expected evidence to be included")
	}
}

func TestJSONReporter_Report_NoEvidence(t *testing.T) {
	reporter := NewJSONReporter(Config{IncludeEvidence: false})
	findings := createTestFindings()

	var buf bytes.Buffer
	err := reporter.Report(context.Background(), findings, &buf)
	if err != nil {
		t.Fatalf("Report failed: %v", err)
	}

	var output JSONOutput
	if err := json.Unmarshal(buf.Bytes(), &output); err != nil {
		t.Fatalf("Invalid JSON output: %v", err)
	}

	// Verify evidence is not included
	if output.Findings[0].Evidence != nil {
		t.Error("Expected evidence to not be included")
	}
}

func TestJSONReporter_Report_Empty(t *testing.T) {
	reporter := NewJSONReporter(Config{})
	var findings []domain.Finding

	var buf bytes.Buffer
	err := reporter.Report(context.Background(), findings, &buf)
	if err != nil {
		t.Fatalf("Report failed: %v", err)
	}

	var output JSONOutput
	if err := json.Unmarshal(buf.Bytes(), &output); err != nil {
		t.Fatalf("Invalid JSON output: %v", err)
	}

	if output.Summary.Total != 0 {
		t.Errorf("Expected total 0, got %d", output.Summary.Total)
	}
}

func TestCSVReporter_Report(t *testing.T) {
	reporter := NewCSVReporter(Config{})
	findings := createTestFindings()

	var buf bytes.Buffer
	err := reporter.Report(context.Background(), findings, &buf)
	if err != nil {
		t.Fatalf("Report failed: %v", err)
	}

	output := buf.String()

	// Verify header
	if !strings.Contains(output, "ID,Severity,Status") {
		t.Error("CSV should contain header row")
	}

	// Verify data rows
	lines := strings.Split(strings.TrimSpace(output), "\n")
	if len(lines) != 3 { // header + 2 findings
		t.Errorf("Expected 3 lines, got %d", len(lines))
	}

	// Verify first finding data
	if !strings.Contains(output, "test-finding-1") {
		t.Error("CSV should contain finding ID")
	}
	if !strings.Contains(output, "CRITICAL") {
		t.Error("CSV should contain severity")
	}
	if !strings.Contains(output, "cdn.example.com.") {
		t.Error("CSV should contain record name")
	}
}

func TestCSVReporter_Report_Empty(t *testing.T) {
	reporter := NewCSVReporter(Config{})
	var findings []domain.Finding

	var buf bytes.Buffer
	err := reporter.Report(context.Background(), findings, &buf)
	if err != nil {
		t.Fatalf("Report failed: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 1 { // Just header
		t.Errorf("Expected 1 line (header only), got %d", len(lines))
	}
}

func TestConsoleReporter_Report(t *testing.T) {
	reporter := NewConsoleReporter(Config{Verbose: true, IncludeEvidence: true})
	findings := createTestFindings()

	var buf bytes.Buffer
	err := reporter.Report(context.Background(), findings, &buf)
	if err != nil {
		t.Fatalf("Report failed: %v", err)
	}

	output := buf.String()

	// Verify summary section
	if !strings.Contains(output, "Total Findings: 2") {
		t.Error("Output should contain total findings count")
	}

	// Verify finding details
	if !strings.Contains(output, "cdn.example.com.") {
		t.Error("Output should contain record name")
	}
	if !strings.Contains(output, "mybucket.s3.amazonaws.com") {
		t.Error("Output should contain target")
	}
	if !strings.Contains(output, "aws-s3") {
		t.Error("Output should contain provider")
	}

	// Verify evidence is shown
	if !strings.Contains(output, "checker") {
		t.Error("Output should contain evidence when enabled")
	}
}

func TestConsoleReporter_Report_Empty(t *testing.T) {
	reporter := NewConsoleReporter(Config{})
	var findings []domain.Finding

	var buf bytes.Buffer
	err := reporter.Report(context.Background(), findings, &buf)
	if err != nil {
		t.Fatalf("Report failed: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "No dangling DNS records found") {
		t.Error("Output should indicate no findings")
	}
}

func TestSupportedFormats(t *testing.T) {
	formats := SupportedFormats()

	expected := []string{"json", "csv", "console"}
	if len(formats) != len(expected) {
		t.Errorf("Expected %d formats, got %d", len(expected), len(formats))
	}

	for _, e := range expected {
		found := false
		for _, f := range formats {
			if f == e {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected format %q not found", e)
		}
	}
}

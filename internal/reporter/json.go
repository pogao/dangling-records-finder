package reporter

import (
	"context"
	"encoding/json"
	"io"
	"time"

	"github.com/pogao/dangling-records-finder/internal/domain"
)

// JSONReporter outputs findings as JSON.
type JSONReporter struct {
	config Config
}

// NewJSONReporter creates a new JSON reporter.
func NewJSONReporter(config Config) *JSONReporter {
	return &JSONReporter{config: config}
}

// Format returns the output format name.
func (r *JSONReporter) Format() string {
	return "json"
}

// JSONOutput represents the JSON output structure.
type JSONOutput struct {
	Metadata JSONMetadata  `json:"metadata"`
	Summary  JSONSummary   `json:"summary"`
	Findings []JSONFinding `json:"findings"`
}

// JSONMetadata contains report metadata.
type JSONMetadata struct {
	GeneratedAt string `json:"generated_at"`
	Version     string `json:"version"`
}

// JSONSummary contains finding counts by severity.
type JSONSummary struct {
	Total    int `json:"total"`
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Info     int `json:"info"`
}

// JSONFinding represents a single finding in JSON format.
type JSONFinding struct {
	ID           string            `json:"id"`
	Severity     string            `json:"severity"`
	Status       string            `json:"status"`
	RecordName   string            `json:"record_name"`
	RecordType   string            `json:"record_type"`
	RecordZone   string            `json:"record_zone"`
	Target       string            `json:"target"`
	Provider     string            `json:"provider"`
	ResourceType string            `json:"resource_type"`
	Title        string            `json:"title"`
	Description  string            `json:"description"`
	Remediation  string            `json:"remediation"`
	Evidence     map[string]string `json:"evidence,omitempty"`
	DetectedAt   string            `json:"detected_at"`
}

// Report writes findings as JSON to the given writer.
func (r *JSONReporter) Report(ctx context.Context, findings []domain.Finding, w io.Writer) error {
	output := JSONOutput{
		Metadata: JSONMetadata{
			GeneratedAt: time.Now().UTC().Format(time.RFC3339),
			Version:     "1.0.0",
		},
		Summary:  r.calculateSummary(findings),
		Findings: r.convertFindings(findings),
	}

	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(output)
}

func (r *JSONReporter) calculateSummary(findings []domain.Finding) JSONSummary {
	summary := JSONSummary{Total: len(findings)}

	for _, f := range findings {
		switch f.Severity {
		case domain.SeverityCritical:
			summary.Critical++
		case domain.SeverityHigh:
			summary.High++
		case domain.SeverityMedium:
			summary.Medium++
		case domain.SeverityLow:
			summary.Low++
		case domain.SeverityInfo:
			summary.Info++
		}
	}

	return summary
}

func (r *JSONReporter) convertFindings(findings []domain.Finding) []JSONFinding {
	result := make([]JSONFinding, len(findings))

	for i, f := range findings {
		jf := JSONFinding{
			ID:           f.ID,
			Severity:     string(f.Severity),
			Status:       string(f.Status),
			Target:       f.Target,
			Provider:     f.Provider,
			ResourceType: f.ResourceType,
			Title:        f.Title,
			Description:  f.Description,
			Remediation:  f.Remediation,
			DetectedAt:   f.DetectedAt.Format(time.RFC3339),
		}

		if f.Record != nil {
			jf.RecordName = f.Record.Name
			jf.RecordType = string(f.Record.Type)
			jf.RecordZone = f.Record.Zone
		}

		if r.config.IncludeEvidence && len(f.Evidence) > 0 {
			jf.Evidence = f.Evidence
		}

		result[i] = jf
	}

	return result
}

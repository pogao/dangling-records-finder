package reporter

import (
	"context"
	"encoding/csv"
	"io"

	"github.com/pogao/dangling-records-finder/internal/domain"
)

// CSVReporter outputs findings as CSV.
type CSVReporter struct {
	config Config
}

// NewCSVReporter creates a new CSV reporter.
func NewCSVReporter(config Config) *CSVReporter {
	return &CSVReporter{config: config}
}

// Format returns the output format name.
func (r *CSVReporter) Format() string {
	return "csv"
}

// Report writes findings as CSV to the given writer.
func (r *CSVReporter) Report(ctx context.Context, findings []domain.Finding, w io.Writer) error {
	writer := csv.NewWriter(w)
	defer writer.Flush()

	// Write header
	header := []string{
		"ID",
		"Severity",
		"Status",
		"Record Name",
		"Record Type",
		"Record Zone",
		"Target",
		"Provider",
		"Resource Type",
		"Title",
		"Description",
		"Remediation",
		"Detected At",
	}

	if err := writer.Write(header); err != nil {
		return err
	}

	// Write findings
	for _, f := range findings {
		recordName := ""
		recordType := ""
		recordZone := ""
		if f.Record != nil {
			recordName = f.Record.Name
			recordType = string(f.Record.Type)
			recordZone = f.Record.Zone
		}

		row := []string{
			f.ID,
			string(f.Severity),
			string(f.Status),
			recordName,
			recordType,
			recordZone,
			f.Target,
			f.Provider,
			f.ResourceType,
			f.Title,
			f.Description,
			f.Remediation,
			f.DetectedAt.Format("2006-01-02T15:04:05Z"),
		}

		if err := writer.Write(row); err != nil {
			return err
		}
	}

	return writer.Error()
}

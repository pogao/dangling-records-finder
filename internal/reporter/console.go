package reporter

import (
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/fatih/color"
	"github.com/pogao/dangling-records-finder/internal/domain"
)

// ConsoleReporter outputs findings in human-readable format.
type ConsoleReporter struct {
	config Config
}

// NewConsoleReporter creates a new console reporter.
func NewConsoleReporter(config Config) *ConsoleReporter {
	return &ConsoleReporter{config: config}
}

// Format returns the output format name.
func (r *ConsoleReporter) Format() string {
	return "console"
}

// Report writes findings in human-readable format to the given writer.
func (r *ConsoleReporter) Report(ctx context.Context, findings []domain.Finding, w io.Writer) error {
	if len(findings) == 0 {
		fmt.Fprintln(w, color.GreenString("No dangling DNS records found."))
		return nil
	}

	// Print summary
	r.printSummary(findings, w)

	// Print each finding
	for i, f := range findings {
		r.printFinding(i+1, f, w)
	}

	return nil
}

func (r *ConsoleReporter) printSummary(findings []domain.Finding, w io.Writer) {
	fmt.Fprintln(w, strings.Repeat("=", 70))
	fmt.Fprintln(w, color.New(color.Bold).Sprint("Dangling DNS Records Report"))
	fmt.Fprintln(w, strings.Repeat("=", 70))
	fmt.Fprintln(w)

	// Count by severity
	var critical, high, medium, low, info int
	for _, f := range findings {
		switch f.Severity {
		case domain.SeverityCritical:
			critical++
		case domain.SeverityHigh:
			high++
		case domain.SeverityMedium:
			medium++
		case domain.SeverityLow:
			low++
		case domain.SeverityInfo:
			info++
		}
	}

	fmt.Fprintf(w, "Total Findings: %d\n", len(findings))
	if critical > 0 {
		fmt.Fprintf(w, "  %s: %d\n", color.RedString("CRITICAL"), critical)
	}
	if high > 0 {
		fmt.Fprintf(w, "  %s: %d\n", color.New(color.FgHiRed).Sprint("HIGH"), high)
	}
	if medium > 0 {
		fmt.Fprintf(w, "  %s: %d\n", color.YellowString("MEDIUM"), medium)
	}
	if low > 0 {
		fmt.Fprintf(w, "  %s: %d\n", color.BlueString("LOW"), low)
	}
	if info > 0 {
		fmt.Fprintf(w, "  %s: %d\n", color.CyanString("INFO"), info)
	}

	fmt.Fprintln(w)
	fmt.Fprintln(w, strings.Repeat("-", 70))
	fmt.Fprintln(w)
}

func (r *ConsoleReporter) printFinding(num int, f domain.Finding, w io.Writer) {
	// Severity color
	severityStr := r.colorSeverity(f.Severity)

	fmt.Fprintf(w, "[%d] %s\n", num, severityStr)
	fmt.Fprintf(w, "    Title:       %s\n", f.Title)

	if f.Record != nil {
		fmt.Fprintf(w, "    Record:      %s (%s)\n", f.Record.Name, f.Record.Type)
		fmt.Fprintf(w, "    Zone:        %s\n", f.Record.Zone)
	}

	fmt.Fprintf(w, "    Target:      %s\n", f.Target)
	fmt.Fprintf(w, "    Provider:    %s\n", f.Provider)
	fmt.Fprintf(w, "    Status:      %s\n", r.colorStatus(f.Status))

	if r.config.Verbose {
		fmt.Fprintf(w, "    Description: %s\n", f.Description)
	}

	fmt.Fprintf(w, "    Remediation: %s\n", f.Remediation)

	if r.config.IncludeEvidence && len(f.Evidence) > 0 {
		fmt.Fprintf(w, "    Evidence:\n")
		for k, v := range f.Evidence {
			fmt.Fprintf(w, "      - %s: %s\n", k, v)
		}
	}

	fmt.Fprintln(w)
}

func (r *ConsoleReporter) colorSeverity(s domain.Severity) string {
	switch s {
	case domain.SeverityCritical:
		return color.New(color.FgWhite, color.BgRed, color.Bold).Sprint(" CRITICAL ")
	case domain.SeverityHigh:
		return color.New(color.FgWhite, color.BgHiRed).Sprint(" HIGH ")
	case domain.SeverityMedium:
		return color.New(color.FgBlack, color.BgYellow).Sprint(" MEDIUM ")
	case domain.SeverityLow:
		return color.New(color.FgWhite, color.BgBlue).Sprint(" LOW ")
	case domain.SeverityInfo:
		return color.New(color.FgWhite, color.BgCyan).Sprint(" INFO ")
	default:
		return string(s)
	}
}

func (r *ConsoleReporter) colorStatus(s domain.ResourceStatus) string {
	switch s {
	case domain.ResourceStatusClaimable:
		return color.RedString("CLAIMABLE - Subdomain takeover possible!")
	case domain.ResourceStatusExists:
		return color.GreenString("EXISTS")
	case domain.ResourceStatusUnknown:
		return color.YellowString("UNKNOWN")
	case domain.ResourceStatusError:
		return color.RedString("ERROR")
	default:
		return string(s)
	}
}

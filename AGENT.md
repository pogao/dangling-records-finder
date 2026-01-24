# AGENT.md - Development Guidelines for Dangling DNS Records Finder

## Project Overview

This tool identifies dangling DNS records that could lead to subdomain takeover vulnerabilities. It parses DNS zone files, analyzes records (CNAME, A, AAAA, ALIAS), and detects when they point to decommissioned or unclaimed resources.

### Security Context

Dangling DNS records occur when:
- A CNAME points to a deleted cloud resource (S3 bucket, Azure blob, GitHub Pages, etc.)
- An A/AAAA record points to an IP address no longer controlled by the organization
- An ALIAS record references a deprovisioned service

These create subdomain takeover risks where attackers can claim the orphaned destination and serve malicious content under the organization's trusted domain.

---

## Development Philosophy

### Critical Rules for the LLM Assistant

1. **Challenge Bad Ideas**: If a proposed approach is suboptimal, insecure, or violates best practices, say so directly and offer alternatives. Do not validate poor decisions.

2. **Plan Before Code**: Before writing any code, present a detailed plan including:
   - Files to create/modify
   - Package structure changes
   - Interface definitions
   - Dependencies to add
   - Test strategy

   Wait for explicit approval before proceeding.

3. **Extended Thinking Required**: Always use extended thinking (ultrathink) before providing answers or generating code. Complex problems require deep analysis.

---

## Go Version and Dependencies

- **Go Version**: 1.23.x (latest stable)
- Update `go.mod` to use `go 1.23`
- Prefer standard library solutions over third-party dependencies when reasonable
- Vet all dependencies for security and maintenance status

---

## Architecture Principles

### Clean Architecture

The codebase must follow clean architecture with clear separation of concerns:

```
dangling-records-finder/
├── cmd/
│   └── drf/                    # Main application entry point
│       └── main.go
├── internal/
│   ├── domain/                 # Core business entities and interfaces
│   │   ├── record.go           # DNS record domain models
│   │   ├── zone.go             # Zone domain models
│   │   ├── finding.go          # Security finding models
│   │   └── errors.go           # Domain-specific errors
│   ├── parser/                 # Zone file parsing
│   │   ├── parser.go           # Parser interface and implementation
│   │   └── parser_test.go
│   ├── analyzer/               # Dangling record detection logic
│   │   ├── analyzer.go         # Analyzer interface and implementation
│   │   ├── strategies/         # Detection strategies per record type
│   │   │   ├── cname.go
│   │   │   ├── a_record.go
│   │   │   └── alias.go
│   │   └── analyzer_test.go
│   ├── resolver/               # DNS resolution abstraction
│   │   ├── resolver.go         # Interface for DNS lookups
│   │   └── resolver_test.go
│   ├── checker/                # Cloud resource existence checking
│   │   ├── checker.go          # Interface for resource validation
│   │   ├── aws.go              # AWS-specific checks (S3, CloudFront, etc.)
│   │   ├── azure.go            # Azure-specific checks
│   │   ├── gcp.go              # GCP-specific checks
│   │   └── github.go           # GitHub Pages checks
│   ├── reporter/               # Output generation
│   │   ├── reporter.go         # Reporter interface
│   │   ├── json.go
│   │   ├── csv.go
│   │   └── console.go
│   └── config/                 # Configuration management
│       └── config.go
├── pkg/                        # Public packages (if needed for library use)
├── testdata/                   # Test fixtures (sample zone files, etc.)
├── go.mod
├── go.sum
├── Makefile
└── AGENT.md
```

### DRY Principles

- Extract common functionality into shared packages
- Use composition over inheritance
- Create utility functions for repeated operations
- Avoid copy-paste code; if similar logic exists in multiple places, refactor

### Interface-Driven Design

**Every major component must be defined by an interface first.** This is non-negotiable for testability.

```go
// Good: Interface defines behavior
type DNSResolver interface {
    Resolve(ctx context.Context, name string, recordType uint16) ([]string, error)
}

type ZoneParser interface {
    Parse(ctx context.Context, reader io.Reader) (*domain.Zone, error)
}

type ResourceChecker interface {
    CheckAvailability(ctx context.Context, target string) (domain.ResourceStatus, error)
}

type Analyzer interface {
    Analyze(ctx context.Context, zone *domain.Zone) ([]domain.Finding, error)
}

type Reporter interface {
    Report(ctx context.Context, findings []domain.Finding, writer io.Writer) error
}
```

---

## Code Quality Standards

### Naming Conventions

Follow Go conventions strictly:

```go
// Package names: lowercase, single word, no underscores
package analyzer  // Good
package dns_analyzer  // Bad

// Exported identifiers: PascalCase, descriptive
type DNSRecord struct{}  // Good
type Rec struct{}  // Bad - unclear

// Unexported identifiers: camelCase
func parseRecord() {}  // Good

// Interfaces: behavior-based names, often ending in -er
type Resolver interface{}  // Good
type Parser interface{}  // Good

// Avoid stuttering
analyzer.Analyzer  // Acceptable when interface name matches package purpose
analyzer.DNSAnalyzer  // Unnecessary prefix

// Variables: clear and descriptive
recordCount := 10  // Good
rc := 10  // Bad - unclear
```

### Error Handling

Errors must be:
1. **Wrapped with context** using `fmt.Errorf` with `%w`
2. **Actionable** - tell the operator what failed and why
3. **Recoverable where possible** - only panic/fatal for unrecoverable situations

```go
// Good: Wrapped error with context
func (p *Parser) Parse(ctx context.Context, r io.Reader) (*domain.Zone, error) {
    data, err := io.ReadAll(r)
    if err != nil {
        return nil, fmt.Errorf("failed to read zone file data: %w", err)
    }

    zone, err := p.parseZoneData(data)
    if err != nil {
        return nil, fmt.Errorf("failed to parse zone file content: %w", err)
    }

    return zone, nil
}

// Good: Custom error types for specific failure modes
type RecordParseError struct {
    Line       int
    Content    string
    Reason     string
    Underlying error
}

func (e *RecordParseError) Error() string {
    return fmt.Sprintf("parse error at line %d: %s (content: %q)",
        e.Line, e.Reason, e.Content)
}

func (e *RecordParseError) Unwrap() error {
    return e.Underlying
}
```

**When to terminate the application:**
- Configuration file missing or invalid at startup
- Required environment variables not set
- Unable to establish required connections after retries
- Unrecoverable corruption detected

**When to continue with error logging:**
- Individual record parsing failures (skip and log)
- Network timeouts on specific checks (retry, then log and continue)
- Non-critical feature unavailable

### Logging Standards

Use structured logging with `log/slog` (standard library). All logs must be JSON formatted.

```go
import "log/slog"

// Initialize logger at application startup
logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
    Level: slog.LevelInfo,
}))
slog.SetDefault(logger)

// Good: Detailed, actionable log messages
slog.ErrorContext(ctx, "DNS resolution failed for CNAME target",
    slog.String("record_name", record.Name),
    slog.String("record_type", "CNAME"),
    slog.String("target", record.Target),
    slog.String("zone", zone.Name),
    slog.Int("attempt", attemptNumber),
    slog.Duration("elapsed", elapsed),
    slog.String("error", err.Error()),
    slog.String("action", "record will be flagged as potentially dangling"),
)

slog.InfoContext(ctx, "Zone file parsing completed",
    slog.String("zone_file", filePath),
    slog.Int("total_records", len(records)),
    slog.Int("cname_records", cnameCount),
    slog.Int("a_records", aCount),
    slog.Int("parse_errors", errorCount),
    slog.Duration("parse_duration", elapsed),
)

// Bad: Vague, unhelpful logs
slog.Error("error occurred", slog.String("err", err.Error()))  // What error? Where? What now?
slog.Info("done")  // Done with what?
```

**Required log fields by context:**

| Context | Required Fields |
|---------|-----------------|
| Record Processing | record_name, record_type, zone, target |
| DNS Resolution | query_name, query_type, resolver, attempt, latency_ms |
| Resource Check | provider, resource_type, resource_id, status |
| Finding | severity, record_name, vulnerability_type, remediation |
| Error | error, component, operation, action |

---

## Testing Requirements

### Unit Tests

**Every function must have corresponding unit tests.** A task is not complete until tests exist and pass.

```go
// Example: parser_test.go
func TestParser_Parse(t *testing.T) {
    tests := []struct {
        name      string
        input     string
        wantZone  *domain.Zone
        wantErr   bool
        errContains string
    }{
        {
            name: "valid zone with CNAME records",
            input: `$ORIGIN example.com.
www  IN CNAME  webserver.example.com.
mail IN CNAME  mailserver.provider.com.`,
            wantZone: &domain.Zone{
                Origin: "example.com.",
                Records: []domain.Record{
                    {Name: "www", Type: domain.RecordTypeCNAME, Target: "webserver.example.com."},
                    {Name: "mail", Type: domain.RecordTypeCNAME, Target: "mailserver.provider.com."},
                },
            },
            wantErr: false,
        },
        {
            name:      "empty input returns error",
            input:     "",
            wantZone:  nil,
            wantErr:   true,
            errContains: "empty zone file",
        },
        // Add more test cases...
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            p := NewParser()
            got, err := p.Parse(context.Background(), strings.NewReader(tt.input))

            if tt.wantErr {
                if err == nil {
                    t.Fatal("expected error, got nil")
                }
                if tt.errContains != "" && !strings.Contains(err.Error(), tt.errContains) {
                    t.Errorf("error %q should contain %q", err.Error(), tt.errContains)
                }
                return
            }

            if err != nil {
                t.Fatalf("unexpected error: %v", err)
            }

            if diff := cmp.Diff(tt.wantZone, got); diff != "" {
                t.Errorf("Parse() mismatch (-want +got):\n%s", diff)
            }
        })
    }
}
```

### Integration/E2E Tests

Create end-to-end tests that exercise the full pipeline with mocked external dependencies:

```go
func TestFullAnalysisPipeline(t *testing.T) {
    // Mock DNS resolver
    mockResolver := &MockResolver{
        responses: map[string][]string{
            "active.example.com.":   {"192.168.1.1"},
            "dangling.example.com.": {},  // Simulates NXDOMAIN
        },
    }

    // Mock resource checker
    mockChecker := &MockResourceChecker{
        availability: map[string]domain.ResourceStatus{
            "deleted-bucket.s3.amazonaws.com": domain.ResourceStatusUnclaimed,
        },
    }

    analyzer := NewAnalyzer(mockResolver, mockChecker)

    // ... test full pipeline
}
```

### Test Coverage Goals

- Aim for >80% code coverage on business logic
- 100% coverage on security-critical paths (vulnerability detection logic)
- All error paths must be tested

---

## Domain Models

Define clear domain models in `internal/domain/`:

```go
// record.go
package domain

type RecordType string

const (
    RecordTypeA     RecordType = "A"
    RecordTypeAAAA  RecordType = "AAAA"
    RecordTypeCNAME RecordType = "CNAME"
    RecordTypeALIAS RecordType = "ALIAS"
    RecordTypeMX    RecordType = "MX"
    RecordTypeNS    RecordType = "NS"
    RecordTypeTXT   RecordType = "TXT"
)

type Record struct {
    Name     string
    Type     RecordType
    TTL      int
    Target   string     // For CNAME/ALIAS
    Value    string     // For A/AAAA/TXT
    Priority int        // For MX
    Line     int        // Source line number for error reporting
}

// finding.go
type Severity string

const (
    SeverityCritical Severity = "CRITICAL"
    SeverityHigh     Severity = "HIGH"
    SeverityMedium   Severity = "MEDIUM"
    SeverityLow      Severity = "LOW"
    SeverityInfo     Severity = "INFO"
)

type VulnerabilityType string

const (
    VulnSubdomainTakeover VulnerabilityType = "SUBDOMAIN_TAKEOVER"
    VulnOrphanedRecord    VulnerabilityType = "ORPHANED_RECORD"
    VulnExpiredService    VulnerabilityType = "EXPIRED_SERVICE"
)

type Finding struct {
    Record            Record
    VulnerabilityType VulnerabilityType
    Severity          Severity
    Description       string
    Remediation       string
    Provider          string            // e.g., "AWS", "Azure", "GitHub"
    Evidence          map[string]string // Supporting data for the finding
    DetectedAt        time.Time
}

type ResourceStatus string

const (
    ResourceStatusActive    ResourceStatus = "ACTIVE"
    ResourceStatusUnclaimed ResourceStatus = "UNCLAIMED"
    ResourceStatusUnknown   ResourceStatus = "UNKNOWN"
    ResourceStatusError     ResourceStatus = "ERROR"
)
```

---

## Cloud Provider Detection Patterns

The analyzer must detect dangling records for these common patterns:

| Provider | Pattern | Check Method |
|----------|---------|--------------|
| AWS S3 | `*.s3.amazonaws.com`, `*.s3-*.amazonaws.com` | HTTP request for NoSuchBucket |
| AWS CloudFront | `*.cloudfront.net` | DNS + HTTP check |
| AWS Elastic Beanstalk | `*.elasticbeanstalk.com` | DNS resolution |
| Azure Blob | `*.blob.core.windows.net` | HTTP check for BlobNotFound |
| Azure CDN | `*.azureedge.net` | DNS + HTTP check |
| GitHub Pages | `*.github.io` | HTTP 404 check |
| Heroku | `*.herokuapp.com` | DNS + HTTP check |
| Shopify | `*.myshopify.com` | HTTP check |
| Fastly | `*.fastly.net` | DNS resolution |
| Pantheon | `*.pantheonsite.io` | HTTP check |

---

## CLI Interface

The application should support:

```bash
# Basic usage
drf analyze --zone-file /path/to/zone.txt

# With output format
drf analyze --zone-file /path/to/zone.txt --output json --out-file results.json

# With specific checks
drf analyze --zone-file /path/to/zone.txt --check-providers aws,azure,github

# Verbose mode for debugging
drf analyze --zone-file /path/to/zone.txt --verbose

# Configuration file
drf analyze --config /path/to/config.yaml
```

Use `github.com/spf13/cobra` for CLI structure.

---

## Configuration

Support configuration via:
1. Command-line flags (highest priority)
2. Environment variables
3. Configuration file (YAML)

```yaml
# config.yaml
dns:
  timeout: 5s
  retries: 3
  resolvers:
    - 8.8.8.8:53
    - 1.1.1.1:53

checks:
  providers:
    - aws
    - azure
    - gcp
    - github
  concurrency: 10
  timeout_per_check: 10s

output:
  format: json
  include_evidence: true

logging:
  level: info
  format: json
```

---

## Development Workflow

### Before Writing Code

1. **Understand the requirement** - Ask clarifying questions if anything is ambiguous
2. **Research** - Check Go documentation, existing patterns in the codebase
3. **Plan** - Present a detailed implementation plan including:
   - Files to create/modify
   - Interface definitions
   - Function signatures
   - Test strategy
   - Potential edge cases
4. **Get approval** - Wait for explicit confirmation before proceeding

### While Writing Code

1. Write the interface first
2. Write the tests (TDD encouraged but not mandated)
3. Implement the functionality
4. Ensure all tests pass
5. Check for linting issues (`golangci-lint run`)

### After Writing Code

1. Run `go fmt` and `go vet`
2. Run all tests: `go test ./...`
3. Check test coverage: `go test -cover ./...`
4. Review for any hardcoded values, magic numbers, or unclear naming

---

## Common Pitfalls to Avoid

1. **Don't use `panic` for recoverable errors** - Reserve panic for truly unrecoverable situations
2. **Don't ignore errors** - Every error must be handled or explicitly documented why it's ignored
3. **Don't use global state** - Pass dependencies explicitly
4. **Don't hardcode configuration** - Use configuration files or environment variables
5. **Don't skip tests** - No function is complete without tests
6. **Don't use `interface{}` or `any` without strong justification** - Prefer typed interfaces
7. **Don't create god objects** - Keep structs focused on single responsibilities
8. **Don't mix levels of abstraction** - Keep functions at consistent abstraction levels

---

## Reference Documentation

Always consult these authoritative sources:

- [Effective Go](https://go.dev/doc/effective_go)
- [Go Code Review Comments](https://github.com/golang/go/wiki/CodeReviewComments)
- [Go Blog](https://go.dev/blog/)
- [Standard Library Documentation](https://pkg.go.dev/std)
- [Go Proverbs](https://go-proverbs.github.io/)
- [Uber Go Style Guide](https://github.com/uber-go/guide/blob/master/style.md) (community best practices)

---

## Checklist for Task Completion

Before marking any task as complete, verify:

- [ ] Code compiles without errors (`go build ./...`)
- [ ] All tests pass (`go test ./...`)
- [ ] New code has corresponding unit tests
- [ ] Test coverage is adequate for the new code
- [ ] Code passes linting (`golangci-lint run`)
- [ ] No hardcoded secrets or sensitive values
- [ ] Error messages are clear and actionable
- [ ] Log messages include necessary context
- [ ] Interfaces are used where appropriate for testability
- [ ] Documentation comments exist for exported functions/types
- [ ] No `TODO` comments left without associated tracking issue

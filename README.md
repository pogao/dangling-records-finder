# Dangling Records Finder (DRF)

<p align="center">
  <strong>A security tool for detecting subdomain takeover vulnerabilities in DNS configurations</strong>
  <br />
  <p>Please note this is just me playing with AI agents to better understand how to use them better. Not all code was written by me.</p>
</p>

<p align="center">
  <a href="#features">Features</a> •
  <a href="#why-this-matters">Why This Matters</a> •
  <a href="#installation">Installation</a> •
  <a href="#usage">Usage</a> •
  <a href="#architecture">Architecture</a> •
  <a href="#supported-providers">Supported Providers</a>
</p>

---

## Overview

**Dangling Records Finder (DRF)** is a command-line security tool that identifies dangling DNS records—a critical vulnerability class that enables subdomain takeover attacks. It scans DNS configurations from GCP Cloud DNS or standard BIND zone files, identifies records pointing to cloud resources, and determines whether those resources are claimable by attackers.

```
$ drf analyze --source zonefile --file zone.txt

======================================================================
Dangling DNS Records Report
======================================================================

Total Findings: 3
  CRITICAL: 3

[1]  CRITICAL
    Title:       Dangling DNS Record - Subdomain Takeover Possible
    Record:      cdn.example.com. (CNAME)
    Target:      deleted-bucket.s3.amazonaws.com
    Provider:    aws-s3
    Status:      CLAIMABLE - Subdomain takeover possible!
    Remediation: Remove the DNS record or recreate the S3 bucket.
```

## Why This Matters

### The Subdomain Takeover Attack Vector

Subdomain takeover is a **high-severity vulnerability** that occurs when:

1. A DNS record (typically CNAME) points to an external service (S3, Heroku, GitHub Pages, etc.)
2. The external resource is deleted or unclaimed
3. An attacker registers the same resource name on the cloud provider
4. The attacker now controls content served on your subdomain

**Real-world impact includes:**

| Attack Vector             | Business Impact                                                            |
| ------------------------- | -------------------------------------------------------------------------- |
| **Cookie Theft**          | Attacker can set cookies for the parent domain, enabling session hijacking |
| **Credential Harvesting** | Phishing pages on legitimate-looking subdomains                            |
| **Reputation Damage**     | Malicious content served under your brand                                  |
| **SEO Poisoning**         | Spam/malware affecting domain reputation                                   |
| **OAuth Token Theft**     | If subdomain is whitelisted in OAuth configs                               |

### Notable Incidents

- **2020**: Researchers found 400+ Microsoft subdomains vulnerable to takeover
- **2021**: Multiple Fortune 500 companies exposed via abandoned S3 buckets
- **Ongoing**: Bug bounty programs consistently pay $500-$3000+ for subdomain takeover findings

### Why Automate This Check?

Organizations with hundreds of DNS records cannot manually verify each one. DRF automates the detection process, integrating into security workflows and CI/CD pipelines to catch vulnerabilities before attackers do.

## Features

- **Multi-Source Support**: Fetch records from GCP Cloud DNS or parse standard BIND zone files
- **Comprehensive Provider Coverage**: Detects vulnerabilities across 7 major cloud providers
- **Concurrent Scanning**: Parallel resource checking with configurable concurrency
- **Multiple Output Formats**: JSON (for CI/CD), CSV (for reporting), Console (for humans)
- **Extensible Architecture**: Plugin-based checker system for adding new providers
- **Production-Ready**: Proper error handling, timeouts, retries, and rate limiting

## Installation

### From Source

```bash
# Clone the repository
git clone https://github.com/pogao/dangling-records-finder.git
cd dangling-records-finder

# Build
go build -o drf ./cmd/drf

# Or use make
make build
```

### Requirements

- Go 1.23+
- For GCP source: Google Cloud credentials configured (ADC)

## Usage

### Basic Usage

```bash
# Analyze a zone file
drf analyze --source zonefile --file /path/to/zone.txt

# Analyze GCP Cloud DNS
drf analyze --source gcp --project my-gcp-project

# Output as JSON (for CI/CD integration)
drf analyze --source zonefile --file zone.txt --output json --out-file results.json

# Verbose mode with increased concurrency
drf analyze --source zonefile --file zone.txt --verbose --concurrency 20
```

### CLI Reference

```
drf analyze [flags]

Flags:
  -s, --source string       DNS record source (gcp, zonefile)
  -p, --project string      GCP project ID (required for gcp source)
  -f, --file string         Zone file path (required for zonefile source)
  -o, --output string       Output format: json, csv, console (default "console")
      --out-file string     Output file path (default: stdout)
  -c, --concurrency int     Number of concurrent checks (default 10)
  -t, --timeout duration    Timeout per check (default 10s)
  -v, --verbose             Enable verbose output
      --config string       Config file path (YAML)
```

### Configuration File

For complex configurations, use a YAML config file:

```yaml
source:
  type: gcp
  gcp:
    project: my-project
    location: global

dns:
  resolvers: ["8.8.8.8:53", "1.1.1.1:53"]
  timeout: 5s
  retries: 3

checks:
  concurrency: 20
  timeout: 10s
  providers: [aws, azure, github, heroku] # Empty = all providers

output:
  format: json
  include_evidence: true
```

```bash
drf analyze --config config.yaml
```

### Exit Codes

| Code | Meaning                                 |
| ---- | --------------------------------------- |
| 0    | Success, no critical findings           |
| 1    | Error during execution                  |
| 2    | Success, but critical findings detected |

This enables CI/CD integration:

```bash
drf analyze --source zonefile --file zone.txt --output json || echo "Vulnerabilities found!"
```

## Supported Providers

DRF detects dangling records pointing to:

| Provider                  | Resource Type     | Detection Pattern                            | Detection Method               |
| ------------------------- | ----------------- | -------------------------------------------- | ------------------------------ |
| **AWS S3**                | Storage Buckets   | `*.s3.amazonaws.com`, `*.s3-*.amazonaws.com` | HTTP `NoSuchBucket` error      |
| **AWS CloudFront**        | CDN Distributions | `*.cloudfront.net`                           | DNS NXDOMAIN / HTTP errors     |
| **AWS Elastic Beanstalk** | App Environments  | `*.elasticbeanstalk.com`                     | DNS NXDOMAIN                   |
| **Azure Blob Storage**    | Storage Accounts  | `*.blob.core.windows.net`                    | HTTP `AccountNotFound` error   |
| **Azure CDN**             | CDN Endpoints     | `*.azureedge.net`, `*.azurefd.net`           | DNS NXDOMAIN / HTTP errors     |
| **GitHub Pages**          | Static Sites      | `*.github.io`                                | HTTP 404 with specific message |
| **Heroku**                | Applications      | `*.herokuapp.com`                            | HTTP "No such app" response    |

## Architecture

DRF follows clean architecture principles with clear separation of concerns:

```
┌─────────────────────────────────────────────────────────────────┐
│                           CLI Layer                             │
│                        (cmd/drf/main.go)                        │
│         Cobra CLI • Flag parsing • Signal handling              │
└─────────────────────────────────────────────────────────────────┘
                                 │
                                 ▼
┌─────────────────────────────────────────────────────────────────┐
│                       Application Layer                         │
├─────────────────┬─────────────────────┬─────────────────────────┤
│     Source      │      Analyzer       │       Reporter          │
│  (DNS Records)  │  (Orchestration)    │    (Output Gen)         │
├─────────────────┼─────────────────────┼─────────────────────────┤
│ • GCP Cloud DNS │ • Concurrent checks │ • JSON (CI/CD)          │
│ • Zone Files    │ • Rate limiting     │ • CSV (Reporting)       │
│                 │ • Timeout handling  │ • Console (Interactive) │
└─────────────────┴─────────────────────┴─────────────────────────┘
                                 │
                                 ▼
┌─────────────────────────────────────────────────────────────────┐
│                        Domain Layer                             │
├─────────────────┬─────────────────────┬─────────────────────────┤
│     Checker     │      Resolver       │       Domain            │
│   (Registry)    │    (DNS Lookups)    │      (Models)           │
├─────────────────┼─────────────────────┼─────────────────────────┤
│ • AWS S3        │ • Multi-resolver    │ • Record                │
│ • CloudFront    │ • Retry/backoff     │ • Zone                  │
│ • Beanstalk     │ • NXDOMAIN detect   │ • Finding               │
│ • Azure Blob    │                     │ • Severity              │
│ • Azure CDN     │                     │ • ResourceStatus        │
│ • GitHub Pages  │                     │                         │
│ • Heroku        │                     │                         │
└─────────────────┴─────────────────────┴─────────────────────────┘
```

### Design Patterns Used

- **Strategy Pattern**: Interchangeable sources (GCP, zone file) and reporters (JSON, CSV, console)
- **Registry Pattern**: Dynamic checker registration for extensibility
- **Interface Segregation**: Small, focused interfaces (`Source`, `Checker`, `Reporter`, `Resolver`)
- **Dependency Injection**: All components receive dependencies via constructors
- **Concurrent Pipeline**: Fan-out/fan-in pattern for parallel resource checking

### Package Structure

```
cmd/drf/                    # CLI entry point
internal/
├── domain/                 # Core entities (Record, Zone, Finding)
│   ├── record.go          # DNS record model
│   ├── zone.go            # Zone model with helper methods
│   ├── finding.go         # Security finding with severity
│   └── errors.go          # Domain-specific errors
├── source/                 # DNS record sources
│   ├── source.go          # Source interface
│   ├── gcp.go             # GCP Cloud DNS implementation
│   └── zonefile.go        # BIND zone file parser
├── resolver/               # DNS resolution
│   └── resolver.go        # Multi-server resolver with retry
├── checker/                # Cloud resource checkers
│   ├── checker.go         # Registry and base checker
│   ├── aws_s3.go          # S3 bucket checker
│   ├── aws_cloudfront.go  # CloudFront checker
│   └── ...                # Other provider checkers
├── analyzer/               # Core analysis engine
│   └── analyzer.go        # Orchestrates the detection pipeline
├── reporter/               # Output generation
│   ├── reporter.go        # Reporter interface
│   ├── json.go            # JSON output
│   ├── csv.go             # CSV output
│   └── console.go         # Colored terminal output
└── config/                 # Configuration management
    └── config.go          # YAML config loading and validation
```

## Testing

```bash
# Run all tests
make test

# Run tests with coverage
make test-coverage

# Run only unit tests (skip integration)
make test-short

# Run linter
make lint
```

### Test Coverage

The project includes comprehensive tests:

- **Unit tests** for all checkers with pattern matching verification
- **Table-driven tests** following Go best practices
- **Mock HTTP servers** for testing cloud provider responses
- **Integration tests** for DNS resolution (skipped in CI with `-short`)

## CI/CD Integration

### GitHub Actions Example

```yaml
name: Security Scan

on:
  push:
    paths:
      - "dns/**"
  schedule:
    - cron: "0 0 * * *" # Daily scan

jobs:
  dns-audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Setup Go
        uses: actions/setup-go@v5
        with:
          go-version: "1.23"

      - name: Install DRF
        run: go install github.com/pogao/dangling-records-finder/cmd/drf@latest

      - name: Scan DNS Records
        run: |
          drf analyze \
            --source zonefile \
            --file dns/production.zone \
            --output json \
            --out-file results.json

      - name: Upload Results
        uses: actions/upload-artifact@v4
        if: always()
        with:
          name: dns-security-report
          path: results.json

      - name: Fail on Critical Findings
        run: |
          if [ $? -eq 2 ]; then
            echo "::error::Critical subdomain takeover vulnerabilities detected!"
            exit 1
          fi
```

## Extending DRF

### Adding a New Cloud Provider Checker

1. Create a new file in `internal/checker/`:

```go
package checker

import (
    "context"
    "regexp"
    "strings"

    "github.com/pogao/dangling-records-finder/internal/domain"
)

var myProviderPattern = regexp.MustCompile(`^[a-z0-9-]+\.myprovider\.com$`)

type MyProviderChecker struct {
    BaseChecker
}

func NewMyProviderChecker(httpClient *http.Client) *MyProviderChecker {
    return &MyProviderChecker{
        BaseChecker: BaseChecker{
            name:       "my-provider",
            httpClient: httpClient,
        },
    }
}

func (c *MyProviderChecker) MatchesTarget(target string) bool {
    return myProviderPattern.MatchString(strings.ToLower(target))
}

func (c *MyProviderChecker) CheckAvailability(ctx context.Context, target string) (domain.ResourceStatus, error) {
    // Implementation: HTTP check, DNS check, or API call
    // Return ResourceStatusClaimable if the resource can be taken over
}
```

2. Register in `checker.go`:

```go
func NewRegistry(...) *Registry {
    r := &Registry{}
    // ... existing checkers
    r.Register(NewMyProviderChecker(httpClient))
    return r
}
```

## Performance Considerations

- **Concurrency**: Default 10 parallel checks, configurable up to 100+
- **Rate Limiting**: Built-in rate limiting to avoid being blocked
- **Timeouts**: Per-check timeouts prevent hanging on slow resources
- **DNS Caching**: Uses system DNS cache; consider local resolver for high-volume scans

## Security Considerations

- DRF only performs read operations (DNS lookups, HTTP HEAD/GET)
- No authentication tokens are stored or transmitted (except GCP ADC for Cloud DNS)
- Output may contain sensitive subdomain information—handle reports securely
- Consider running from a dedicated security scanning environment

## Contributing

Contributions are welcome! Areas of interest:

- Additional cloud provider checkers (Netlify, Vercel, Fastly, etc.)
- Alternative DNS sources (AWS Route53, Azure DNS, Cloudflare)
- Enhanced fingerprinting for edge cases
- Performance optimizations

## License

MIT License - see [LICENSE](LICENSE) for details.

## Acknowledgments

- Inspired by research from [can-i-take-over-xyz](https://github.com/EdOverflow/can-i-take-over-xyz)
- Built with [miekg/dns](https://github.com/miekg/dns) for DNS parsing
- CLI powered by [spf13/cobra](https://github.com/spf13/cobra)

---

<p align="center">
  <strong>Protect your domains. Prevent subdomain takeover.</strong>
</p>

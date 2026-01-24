// Package main provides the CLI entry point for the dangling records finder.
package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/pogao/dangling-records-finder/internal/analyzer"
	"github.com/pogao/dangling-records-finder/internal/checker"
	"github.com/pogao/dangling-records-finder/internal/config"
	"github.com/pogao/dangling-records-finder/internal/reporter"
	"github.com/pogao/dangling-records-finder/internal/resolver"
	"github.com/pogao/dangling-records-finder/internal/source"
)

var (
	version = "1.0.0"

	// CLI flags
	flagSource      string
	flagProject     string
	flagFile        string
	flagOutput      string
	flagOutFile     string
	flagConcurrency int
	flagTimeout     time.Duration
	flagVerbose     bool
	flagConfigFile  string
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "drf",
		Short: "Dangling Records Finder - Detect subdomain takeover vulnerabilities",
		Long: `DRF (Dangling Records Finder) scans DNS records to identify dangling DNS entries
that could be exploited for subdomain takeover attacks.

It supports fetching DNS records from GCP Cloud DNS or parsing local zone files,
then checks if the targets (cloud resources) are claimable by attackers.`,
		Version: version,
	}

	analyzeCmd := &cobra.Command{
		Use:   "analyze",
		Short: "Analyze DNS records for subdomain takeover vulnerabilities",
		Long: `Analyze DNS records to identify dangling entries pointing to claimable cloud resources.

Examples:
  # Analyze a zone file
  drf analyze --source zonefile --file /path/to/zone.txt

  # Analyze GCP Cloud DNS
  drf analyze --source gcp --project my-gcp-project

  # Use a config file
  drf analyze --config config.yaml

  # Output as JSON
  drf analyze --source zonefile --file zone.txt --output json --out-file results.json`,
		RunE: runAnalyze,
	}

	// Add flags to analyze command
	analyzeCmd.Flags().StringVarP(&flagSource, "source", "s", "", "DNS record source (gcp, zonefile)")
	analyzeCmd.Flags().StringVarP(&flagProject, "project", "p", "", "GCP project ID (required for gcp source)")
	analyzeCmd.Flags().StringVarP(&flagFile, "file", "f", "", "Zone file path (required for zonefile source)")
	analyzeCmd.Flags().StringVarP(&flagOutput, "output", "o", "console", "Output format (json, csv, console)")
	analyzeCmd.Flags().StringVar(&flagOutFile, "out-file", "", "Output file path (default: stdout)")
	analyzeCmd.Flags().IntVarP(&flagConcurrency, "concurrency", "c", 10, "Number of concurrent checks")
	analyzeCmd.Flags().DurationVarP(&flagTimeout, "timeout", "t", 10*time.Second, "Timeout per check")
	analyzeCmd.Flags().BoolVarP(&flagVerbose, "verbose", "v", false, "Enable verbose output")
	analyzeCmd.Flags().StringVar(&flagConfigFile, "config", "", "Config file path")

	rootCmd.AddCommand(analyzeCmd)

	// Add version command
	versionCmd := &cobra.Command{
		Use:   "version",
		Short: "Print version information",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("drf version %s\n", version)
		},
	}
	rootCmd.AddCommand(versionCmd)

	// Add providers command
	providersCmd := &cobra.Command{
		Use:   "providers",
		Short: "List supported cloud providers",
		Run: func(cmd *cobra.Command, args []string) {
			registry := checker.NewRegistry(nil, nil)
			fmt.Println("Supported cloud providers:")
			for _, name := range registry.CheckerNames() {
				fmt.Printf("  - %s\n", name)
			}
		},
	}
	rootCmd.AddCommand(providersCmd)

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func runAnalyze(cmd *cobra.Command, args []string) error {
	// Load configuration
	cfg, err := loadConfig()
	if err != nil {
		return fmt.Errorf("loading configuration: %w", err)
	}

	// Validate configuration
	if err := cfg.Validate(); err != nil {
		return err
	}

	// Setup context with cancellation
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle interrupt signals
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		if cfg.Verbose {
			log.Println("Received interrupt signal, shutting down...")
		}
		cancel()
	}()

	// Create DNS resolver
	resolv := resolver.New(resolver.Config{
		Servers:      cfg.DNS.Resolvers,
		Timeout:      cfg.DNS.Timeout,
		Retries:      cfg.DNS.Retries,
		RetryBackoff: 100 * time.Millisecond,
	})

	// Create HTTP client
	httpClient := &http.Client{
		Timeout: cfg.Checks.Timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// Create checker registry
	registry := checker.NewRegistry(httpClient, resolv)

	// Create source
	src, err := createSource(cfg)
	if err != nil {
		return err
	}

	if cfg.Verbose {
		log.Printf("Using source: %s", src.Name())
	}

	// Fetch DNS records
	if cfg.Verbose {
		log.Println("Fetching DNS records...")
	}

	zones, err := src.FetchRecords(ctx)
	if err != nil {
		return fmt.Errorf("fetching records: %w", err)
	}

	if cfg.Verbose {
		totalRecords := 0
		for _, z := range zones {
			totalRecords += len(z.Records)
		}
		log.Printf("Fetched %d records from %d zones", totalRecords, len(zones))
	}

	// Create analyzer
	ana := analyzer.New(registry, resolv, analyzer.Config{
		Concurrency:      cfg.Checks.Concurrency,
		Timeout:          cfg.Checks.Timeout,
		Verbose:          cfg.Verbose,
		EnabledProviders: cfg.Checks.Providers,
		RateLimit:        cfg.Checks.RateLimit,
	})

	// Analyze records
	if cfg.Verbose {
		log.Println("Analyzing records for dangling DNS entries...")
	}

	findings, err := ana.Analyze(ctx, zones)
	if err != nil {
		return fmt.Errorf("analyzing records: %w", err)
	}

	// Create reporter
	rep, err := reporter.NewReporter(cfg.Output.Format, reporter.Config{
		IncludeEvidence: cfg.Output.IncludeEvidence,
		Verbose:         cfg.Verbose,
	})
	if err != nil {
		return err
	}

	// Determine output writer
	var writer io.Writer = os.Stdout
	if cfg.Output.File != "" {
		f, err := os.Create(cfg.Output.File)
		if err != nil {
			return fmt.Errorf("creating output file: %w", err)
		}
		defer f.Close()
		writer = f
	}

	// Generate report
	if err := rep.Report(ctx, findings, writer); err != nil {
		return fmt.Errorf("generating report: %w", err)
	}

	// Exit with non-zero status if critical findings were found
	for _, f := range findings {
		if f.IsCritical() {
			os.Exit(2)
		}
	}

	return nil
}

func loadConfig() (*config.Config, error) {
	var cfg *config.Config
	var err error

	// Load from file if specified
	if flagConfigFile != "" {
		cfg, err = config.LoadFromFile(flagConfigFile)
		if err != nil {
			return nil, err
		}
	} else {
		cfg = config.DefaultConfig()
	}

	// Merge CLI flags
	flags := &config.CLIFlags{
		Source:      flagSource,
		Project:     flagProject,
		File:        flagFile,
		Output:      flagOutput,
		OutFile:     flagOutFile,
		Concurrency: flagConcurrency,
		Timeout:     flagTimeout,
		Verbose:     flagVerbose,
		ConfigFile:  flagConfigFile,
	}
	cfg.Merge(flags)

	return cfg, nil
}

func createSource(cfg *config.Config) (source.Source, error) {
	switch cfg.Source.Type {
	case "gcp":
		return source.NewGCPSource(source.GCPConfig{
			ProjectID: cfg.Source.GCP.Project,
			Location:  cfg.Source.GCP.Location,
			Verbose:   cfg.Verbose,
		}), nil
	case "zonefile":
		return source.NewZoneFileSource(source.ZoneFileConfig{
			FilePath: cfg.Source.ZoneFile.Path,
			Verbose:  cfg.Verbose,
		}), nil
	default:
		return nil, fmt.Errorf("unknown source type: %s", cfg.Source.Type)
	}
}

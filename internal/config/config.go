// Package config provides configuration loading and validation.
package config

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// Config represents the application configuration.
type Config struct {
	Source  SourceConfig  `yaml:"source"`
	DNS     DNSConfig     `yaml:"dns"`
	Checks  ChecksConfig  `yaml:"checks"`
	Output  OutputConfig  `yaml:"output"`
	Verbose bool          `yaml:"verbose"`
}

// SourceConfig contains source-specific configuration.
type SourceConfig struct {
	Type     string         `yaml:"type"` // "gcp" or "zonefile"
	GCP      GCPConfig      `yaml:"gcp"`
	ZoneFile ZoneFileConfig `yaml:"zonefile"`
}

// GCPConfig contains GCP Cloud DNS configuration.
type GCPConfig struct {
	Project  string `yaml:"project"`
	Location string `yaml:"location"` // defaults to "global"
}

// ZoneFileConfig contains zone file source configuration.
type ZoneFileConfig struct {
	Path string `yaml:"path"`
}

// DNSConfig contains DNS resolver configuration.
type DNSConfig struct {
	Resolvers []string      `yaml:"resolvers"`
	Timeout   time.Duration `yaml:"timeout"`
	Retries   int           `yaml:"retries"`
}

// ChecksConfig contains resource checking configuration.
type ChecksConfig struct {
	Concurrency int           `yaml:"concurrency"`
	Timeout     time.Duration `yaml:"timeout"`
	Providers   []string      `yaml:"providers"` // empty = all providers
	RateLimit   time.Duration `yaml:"rate_limit"`
}

// OutputConfig contains output configuration.
type OutputConfig struct {
	Format          string `yaml:"format"` // "json", "csv", "console"
	File            string `yaml:"file"`   // output file path (empty = stdout)
	IncludeEvidence bool   `yaml:"include_evidence"`
}

// DefaultConfig returns a configuration with sensible defaults.
func DefaultConfig() *Config {
	return &Config{
		Source: SourceConfig{
			Type: "zonefile",
			GCP: GCPConfig{
				Location: "global",
			},
		},
		DNS: DNSConfig{
			Resolvers: []string{"8.8.8.8:53", "1.1.1.1:53"},
			Timeout:   5 * time.Second,
			Retries:   3,
		},
		Checks: ChecksConfig{
			Concurrency: 10,
			Timeout:     10 * time.Second,
			RateLimit:   100 * time.Millisecond,
		},
		Output: OutputConfig{
			Format:          "console",
			IncludeEvidence: false,
		},
		Verbose: false,
	}
}

// LoadFromFile loads configuration from a YAML file.
func LoadFromFile(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config file: %w", err)
	}

	config := DefaultConfig()
	if err := yaml.Unmarshal(data, config); err != nil {
		return nil, fmt.Errorf("parsing config file: %w", err)
	}

	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("validating config: %w", err)
	}

	return config, nil
}

// Validate checks the configuration for errors.
func (c *Config) Validate() error {
	switch c.Source.Type {
	case "gcp":
		if c.Source.GCP.Project == "" {
			return fmt.Errorf("GCP project is required when source type is 'gcp'")
		}
	case "zonefile":
		if c.Source.ZoneFile.Path == "" {
			return fmt.Errorf("zone file path is required when source type is 'zonefile'")
		}
	case "":
		return fmt.Errorf("source type is required")
	default:
		return fmt.Errorf("unknown source type: %s (valid: gcp, zonefile)", c.Source.Type)
	}

	if c.Checks.Concurrency < 1 {
		c.Checks.Concurrency = 1
	}

	if c.Checks.Timeout < time.Second {
		c.Checks.Timeout = 10 * time.Second
	}

	validFormats := map[string]bool{"json": true, "csv": true, "console": true, "text": true, "": true}
	if !validFormats[c.Output.Format] {
		return fmt.Errorf("unknown output format: %s (valid: json, csv, console)", c.Output.Format)
	}

	return nil
}

// Merge merges CLI flags into the configuration.
// CLI flags take precedence over config file values.
func (c *Config) Merge(flags *CLIFlags) {
	if flags == nil {
		return
	}

	// Source settings
	if flags.Source != "" {
		c.Source.Type = flags.Source
	}
	if flags.Project != "" {
		c.Source.GCP.Project = flags.Project
	}
	if flags.File != "" {
		c.Source.ZoneFile.Path = flags.File
	}

	// Check settings
	if flags.Concurrency > 0 {
		c.Checks.Concurrency = flags.Concurrency
	}
	if flags.Timeout > 0 {
		c.Checks.Timeout = flags.Timeout
	}

	// Output settings
	if flags.Output != "" {
		c.Output.Format = flags.Output
	}
	if flags.OutFile != "" {
		c.Output.File = flags.OutFile
	}

	// Global settings
	if flags.Verbose {
		c.Verbose = true
	}
}

// CLIFlags represents command-line flags that can override config values.
type CLIFlags struct {
	Source      string
	Project     string
	File        string
	Output      string
	OutFile     string
	Concurrency int
	Timeout     time.Duration
	Verbose     bool
	ConfigFile  string
}

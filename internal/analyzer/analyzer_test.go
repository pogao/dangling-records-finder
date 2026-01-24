package analyzer

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/pogao/dangling-records-finder/internal/checker"
	"github.com/pogao/dangling-records-finder/internal/domain"
	"github.com/pogao/dangling-records-finder/internal/resolver"
)

func TestDefaultAnalyzer_Analyze_NoRecords(t *testing.T) {
	registry := checker.NewRegistry(nil, nil)
	resolv := resolver.New(resolver.DefaultConfig())
	analyzer := New(registry, resolv, DefaultConfig())

	zones := []*domain.Zone{
		{
			Name: "example.com.",
			Records: []*domain.Record{
				{Name: "example.com.", Type: domain.RecordTypeSOA, Values: []string{"ns1.example.com. admin.example.com. 1 3600 900 604800 300"}},
			},
		},
	}

	findings, err := analyzer.Analyze(context.Background(), zones)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	if len(findings) != 0 {
		t.Errorf("Expected 0 findings, got %d", len(findings))
	}
}

func TestDefaultAnalyzer_Analyze_NoMatchingCheckers(t *testing.T) {
	registry := checker.NewRegistry(nil, nil)
	resolv := resolver.New(resolver.DefaultConfig())
	analyzer := New(registry, resolv, DefaultConfig())

	zones := []*domain.Zone{
		{
			Name: "example.com.",
			Records: []*domain.Record{
				{Name: "cdn.example.com.", Type: domain.RecordTypeCNAME, Values: []string{"cdn.someunknownprovider.com"}},
			},
		},
	}

	findings, err := analyzer.Analyze(context.Background(), zones)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	if len(findings) != 0 {
		t.Errorf("Expected 0 findings for unknown provider, got %d", len(findings))
	}
}

func TestDefaultAnalyzer_Analyze_WithEnabledProviders(t *testing.T) {
	registry := checker.NewRegistry(nil, nil)
	resolv := resolver.New(resolver.DefaultConfig())

	config := DefaultConfig()
	config.EnabledProviders = []string{"github-pages"} // Only check GitHub Pages

	analyzer := New(registry, resolv, config)

	// zones would be used for Analyze(), but we're testing shouldCheck() directly
	_ = []*domain.Zone{
		{
			Name: "example.com.",
			Records: []*domain.Record{
				{Name: "cdn.example.com.", Type: domain.RecordTypeCNAME, Values: []string{"mybucket.s3.amazonaws.com"}},
				{Name: "docs.example.com.", Type: domain.RecordTypeCNAME, Values: []string{"myorg.github.io"}},
			},
		},
	}

	// The S3 target should be skipped because only github-pages is enabled
	if analyzer.shouldCheck("mybucket.s3.amazonaws.com") {
		t.Error("S3 target should not be checked when only github-pages is enabled")
	}

	if !analyzer.shouldCheck("myorg.github.io") {
		t.Error("GitHub Pages target should be checked")
	}
}

func TestDefaultConfig(t *testing.T) {
	config := DefaultConfig()

	if config.Concurrency <= 0 {
		t.Error("Default concurrency should be > 0")
	}
	if config.Timeout <= 0 {
		t.Error("Default timeout should be > 0")
	}
}

func TestNew_DefaultValues(t *testing.T) {
	registry := checker.NewRegistry(nil, nil)
	resolv := resolver.New(resolver.DefaultConfig())

	// Test with zero values
	analyzer := New(registry, resolv, Config{})

	if analyzer.config.Concurrency <= 0 {
		t.Error("Expected default concurrency to be applied")
	}
	if analyzer.config.Timeout <= 0 {
		t.Error("Expected default timeout to be applied")
	}
}

func TestExtractResourceType(t *testing.T) {
	tests := []struct {
		checkerName string
		want        string
	}{
		{"aws-s3", "S3 Bucket"},
		{"aws-cloudfront", "CloudFront Distribution"},
		{"aws-beanstalk", "Elastic Beanstalk Environment"},
		{"azure-blob", "Azure Blob Storage"},
		{"azure-cdn", "Azure CDN Endpoint"},
		{"github-pages", "GitHub Pages Site"},
		{"heroku", "Heroku App"},
		{"unknown", "Cloud Resource"},
	}

	for _, tt := range tests {
		t.Run(tt.checkerName, func(t *testing.T) {
			if got := extractResourceType(tt.checkerName); got != tt.want {
				t.Errorf("extractResourceType(%q) = %q, want %q", tt.checkerName, got, tt.want)
			}
		})
	}
}

// MockChecker implements checker.Checker for testing
type MockChecker struct {
	name         string
	matchFunc    func(target string) bool
	statusToReturn domain.ResourceStatus
	errToReturn  error
}

func (m *MockChecker) Name() string {
	return m.name
}

func (m *MockChecker) MatchesTarget(target string) bool {
	if m.matchFunc != nil {
		return m.matchFunc(target)
	}
	return true
}

func (m *MockChecker) CheckAvailability(ctx context.Context, target string) (domain.ResourceStatus, error) {
	return m.statusToReturn, m.errToReturn
}

func TestDefaultAnalyzer_ShouldCheck(t *testing.T) {
	registry := checker.NewRegistry(nil, nil)
	resolv := resolver.New(resolver.DefaultConfig())

	t.Run("no provider restrictions", func(t *testing.T) {
		analyzer := New(registry, resolv, DefaultConfig())

		// Should check known cloud targets
		if !analyzer.shouldCheck("mybucket.s3.amazonaws.com") {
			t.Error("Should check S3 targets")
		}
		if !analyzer.shouldCheck("myapp.herokuapp.com") {
			t.Error("Should check Heroku targets")
		}

		// Should not check unknown targets
		if analyzer.shouldCheck("example.com") {
			t.Error("Should not check unknown targets")
		}
	})

	t.Run("with provider restrictions", func(t *testing.T) {
		config := DefaultConfig()
		config.EnabledProviders = []string{"aws-s3", "heroku"}
		analyzer := New(registry, resolv, config)

		// Should check enabled providers
		if !analyzer.shouldCheck("mybucket.s3.amazonaws.com") {
			t.Error("Should check S3 targets (enabled)")
		}
		if !analyzer.shouldCheck("myapp.herokuapp.com") {
			t.Error("Should check Heroku targets (enabled)")
		}

		// Should not check disabled providers
		if analyzer.shouldCheck("myorg.github.io") {
			t.Error("Should not check GitHub Pages targets (disabled)")
		}
	})
}

func TestDefaultAnalyzer_Analyze_Integration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// Create a mock server that returns GitHub Pages "no site" response
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`There isn't a GitHub Pages site here.`))
	}))
	defer server.Close()

	httpClient := &http.Client{Timeout: 5 * time.Second}
	registry := checker.NewRegistry(httpClient, nil)
	resolv := resolver.New(resolver.DefaultConfig())

	config := DefaultConfig()
	config.Verbose = true
	analyzer := New(registry, resolv, config)

	// Create test zones with a CNAME pointing to a cloud resource
	zones := []*domain.Zone{
		{
			Name: "example.com.",
			Records: []*domain.Record{
				{
					Name:   "test.example.com.",
					Type:   domain.RecordTypeCNAME,
					Values: []string{"nonexistent-bucket-12345.s3.amazonaws.com"},
				},
			},
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	findings, err := analyzer.Analyze(ctx, zones)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	// We expect at least an attempt to check the target
	// The actual result depends on network conditions
	t.Logf("Found %d findings", len(findings))
	for _, f := range findings {
		t.Logf("Finding: %s -> %s (status: %s)", f.Record.Name, f.Target, f.Status)
	}
}

func TestDefaultAnalyzer_ContextCancellation(t *testing.T) {
	registry := checker.NewRegistry(nil, nil)
	resolv := resolver.New(resolver.DefaultConfig())
	analyzer := New(registry, resolv, DefaultConfig())

	zones := []*domain.Zone{
		{
			Name: "example.com.",
			Records: []*domain.Record{
				{Name: "cdn.example.com.", Type: domain.RecordTypeCNAME, Values: []string{"mybucket.s3.amazonaws.com"}},
			},
		},
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	// Should not hang
	findings, err := analyzer.Analyze(ctx, zones)
	if err != nil {
		t.Logf("Expected cancellation, got: %v", err)
	}
	t.Logf("Findings returned: %d", len(findings))
}

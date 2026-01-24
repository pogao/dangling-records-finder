package resolver

import (
	"context"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestNew_DefaultConfig(t *testing.T) {
	r := New(Config{})

	if len(r.servers) == 0 {
		t.Error("Expected default servers to be set")
	}
	if r.timeout == 0 {
		t.Error("Expected default timeout to be set")
	}
	if r.retries == 0 {
		t.Error("Expected default retries to be set")
	}
}

func TestNew_CustomConfig(t *testing.T) {
	cfg := Config{
		Servers:      []string{"9.9.9.9:53"},
		Timeout:      10 * time.Second,
		Retries:      5,
		RetryBackoff: 200 * time.Millisecond,
	}

	r := New(cfg)

	if len(r.servers) != 1 || r.servers[0] != "9.9.9.9:53" {
		t.Errorf("Expected custom servers, got %v", r.servers)
	}
	if r.timeout != 10*time.Second {
		t.Errorf("Expected 10s timeout, got %v", r.timeout)
	}
	if r.retries != 5 {
		t.Errorf("Expected 5 retries, got %d", r.retries)
	}
}

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	if len(cfg.Servers) != 2 {
		t.Errorf("Expected 2 default servers, got %d", len(cfg.Servers))
	}
	if cfg.Servers[0] != "8.8.8.8:53" {
		t.Errorf("Expected first server to be 8.8.8.8:53, got %s", cfg.Servers[0])
	}
	if cfg.Timeout != 5*time.Second {
		t.Errorf("Expected 5s timeout, got %v", cfg.Timeout)
	}
	if cfg.Retries != 3 {
		t.Errorf("Expected 3 retries, got %d", cfg.Retries)
	}
}

// Integration test - requires network access
func TestDNSResolver_Resolve_Integration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	r := New(DefaultConfig())
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Test resolving a well-known domain
	results, err := r.Resolve(ctx, "google.com", dns.TypeA)
	if err != nil {
		t.Fatalf("Failed to resolve google.com: %v", err)
	}

	if len(results) == 0 {
		t.Error("Expected at least one A record for google.com")
	}

	t.Logf("google.com A records: %v", results)
}

// Integration test for NXDOMAIN detection
func TestDNSResolver_ResolveWithNXDOMAIN_Integration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	r := New(DefaultConfig())
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Test with a domain that should return NXDOMAIN
	_, nxdomain, err := r.ResolveWithNXDOMAIN(ctx, "this-domain-definitely-does-not-exist-12345.com", dns.TypeA)
	if err != nil {
		t.Fatalf("Failed to check NXDOMAIN: %v", err)
	}

	if !nxdomain {
		t.Error("Expected NXDOMAIN for non-existent domain")
	}
}

// Integration test for IsNXDOMAIN helper
func TestDNSResolver_IsNXDOMAIN_Integration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	r := New(DefaultConfig())
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Test with a domain that should exist
	nxdomain, err := r.IsNXDOMAIN(ctx, "google.com")
	if err != nil {
		t.Fatalf("Failed to check google.com: %v", err)
	}
	if nxdomain {
		t.Error("google.com should not return NXDOMAIN")
	}
}

func TestDNSResolver_Resolve_ContextCancellation(t *testing.T) {
	r := New(Config{
		Servers: []string{"8.8.8.8:53"},
		Timeout: 30 * time.Second,
	})

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	_, err := r.Resolve(ctx, "google.com", dns.TypeA)
	if err == nil {
		t.Error("Expected error due to cancelled context")
	}
}

func TestDNSResolver_selectServer(t *testing.T) {
	r := New(Config{
		Servers: []string{"1.1.1.1:53", "8.8.8.8:53", "9.9.9.9:53"},
	})

	servers := make(map[string]int)
	for i := 0; i < 100; i++ {
		server := r.selectServer()
		servers[server]++
	}

	// All servers should be selected at least once in 100 iterations
	if len(servers) < 2 {
		t.Error("Expected multiple servers to be selected")
	}
}

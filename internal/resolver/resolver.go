// Package resolver provides DNS resolution functionality.
package resolver

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/pogao/dangling-records-finder/internal/domain"
)

// Resolver performs DNS lookups.
type Resolver interface {
	// Resolve performs a DNS lookup for the given name and record type.
	Resolve(ctx context.Context, name string, recordType uint16) ([]string, error)

	// ResolveWithNXDOMAIN performs a DNS lookup and returns whether NXDOMAIN was received.
	ResolveWithNXDOMAIN(ctx context.Context, name string, recordType uint16) ([]string, bool, error)
}

// Config contains resolver configuration.
type Config struct {
	// Servers is a list of DNS server addresses (e.g., "8.8.8.8:53").
	Servers []string

	// Timeout is the timeout for each DNS query.
	Timeout time.Duration

	// Retries is the number of retry attempts on failure.
	Retries int

	// RetryBackoff is the initial backoff duration between retries.
	RetryBackoff time.Duration
}

// DefaultConfig returns the default resolver configuration.
func DefaultConfig() Config {
	return Config{
		Servers:      []string{"8.8.8.8:53", "1.1.1.1:53"},
		Timeout:      5 * time.Second,
		Retries:      3,
		RetryBackoff: 100 * time.Millisecond,
	}
}

// DNSResolver implements the Resolver interface using miekg/dns.
type DNSResolver struct {
	servers      []string
	timeout      time.Duration
	retries      int
	retryBackoff time.Duration
	client       *dns.Client
}

// New creates a new DNS resolver with the given configuration.
func New(cfg Config) *DNSResolver {
	if len(cfg.Servers) == 0 {
		cfg.Servers = DefaultConfig().Servers
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = DefaultConfig().Timeout
	}
	if cfg.Retries == 0 {
		cfg.Retries = DefaultConfig().Retries
	}
	if cfg.RetryBackoff == 0 {
		cfg.RetryBackoff = DefaultConfig().RetryBackoff
	}

	return &DNSResolver{
		servers:      cfg.Servers,
		timeout:      cfg.Timeout,
		retries:      cfg.Retries,
		retryBackoff: cfg.RetryBackoff,
		client: &dns.Client{
			Net:     "udp",
			Timeout: cfg.Timeout,
		},
	}
}

// Resolve performs a DNS lookup for the given name and record type.
func (r *DNSResolver) Resolve(ctx context.Context, name string, recordType uint16) ([]string, error) {
	results, _, err := r.ResolveWithNXDOMAIN(ctx, name, recordType)
	return results, err
}

// ResolveWithNXDOMAIN performs a DNS lookup and returns whether NXDOMAIN was received.
func (r *DNSResolver) ResolveWithNXDOMAIN(ctx context.Context, name string, recordType uint16) ([]string, bool, error) {
	// Ensure FQDN format
	if !strings.HasSuffix(name, ".") {
		name = name + "."
	}

	msg := new(dns.Msg)
	msg.SetQuestion(name, recordType)
	msg.RecursionDesired = true

	var lastErr error
	for attempt := 0; attempt <= r.retries; attempt++ {
		if attempt > 0 {
			backoff := r.retryBackoff * time.Duration(1<<uint(attempt-1))
			select {
			case <-ctx.Done():
				return nil, false, ctx.Err()
			case <-time.After(backoff):
			}
		}

		// Try each server
		server := r.selectServer()
		resp, _, err := r.client.ExchangeContext(ctx, msg, server)
		if err != nil {
			lastErr = err
			continue
		}

		// Check for NXDOMAIN
		if resp.Rcode == dns.RcodeNameError {
			return nil, true, nil
		}

		// Check for other errors
		if resp.Rcode != dns.RcodeSuccess {
			lastErr = fmt.Errorf("DNS error: %s", dns.RcodeToString[resp.Rcode])
			continue
		}

		// Extract answers
		var results []string
		for _, ans := range resp.Answer {
			switch v := ans.(type) {
			case *dns.A:
				results = append(results, v.A.String())
			case *dns.AAAA:
				results = append(results, v.AAAA.String())
			case *dns.CNAME:
				results = append(results, strings.TrimSuffix(v.Target, "."))
			case *dns.MX:
				results = append(results, fmt.Sprintf("%d %s", v.Preference, strings.TrimSuffix(v.Mx, ".")))
			case *dns.NS:
				results = append(results, strings.TrimSuffix(v.Ns, "."))
			case *dns.TXT:
				results = append(results, strings.Join(v.Txt, ""))
			}
		}

		return results, false, nil
	}

	if lastErr != nil {
		return nil, false, domain.NewResolutionError(name, dns.TypeToString[recordType], lastErr)
	}
	return nil, false, domain.NewResolutionError(name, dns.TypeToString[recordType], errors.New("no response"))
}

func (r *DNSResolver) selectServer() string {
	return r.servers[rand.Intn(len(r.servers))]
}

// IsNXDOMAIN checks if a hostname resolves to NXDOMAIN.
func (r *DNSResolver) IsNXDOMAIN(ctx context.Context, name string) (bool, error) {
	_, nxdomain, err := r.ResolveWithNXDOMAIN(ctx, name, dns.TypeA)
	if err != nil {
		return false, err
	}
	return nxdomain, nil
}

// ResolveA resolves A records for a hostname.
func (r *DNSResolver) ResolveA(ctx context.Context, name string) ([]net.IP, error) {
	results, err := r.Resolve(ctx, name, dns.TypeA)
	if err != nil {
		return nil, err
	}

	var ips []net.IP
	for _, result := range results {
		if ip := net.ParseIP(result); ip != nil {
			ips = append(ips, ip)
		}
	}
	return ips, nil
}

// ResolveCNAME resolves CNAME records for a hostname.
func (r *DNSResolver) ResolveCNAME(ctx context.Context, name string) (string, error) {
	results, err := r.Resolve(ctx, name, dns.TypeCNAME)
	if err != nil {
		return "", err
	}
	if len(results) > 0 {
		return results[0], nil
	}
	return "", nil
}

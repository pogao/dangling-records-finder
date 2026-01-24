// Package domain contains core domain models for the dangling records finder.
package domain

import "time"

// RecordType represents the type of DNS record.
type RecordType string

const (
	RecordTypeA     RecordType = "A"
	RecordTypeAAAA  RecordType = "AAAA"
	RecordTypeCNAME RecordType = "CNAME"
	RecordTypeMX    RecordType = "MX"
	RecordTypeNS    RecordType = "NS"
	RecordTypeTXT   RecordType = "TXT"
	RecordTypeSOA   RecordType = "SOA"
	RecordTypeSRV   RecordType = "SRV"
)

// Record represents a DNS record.
type Record struct {
	// Name is the fully qualified domain name (FQDN) of the record.
	Name string

	// Type is the DNS record type (A, AAAA, CNAME, etc.).
	Type RecordType

	// TTL is the time-to-live in seconds.
	TTL uint32

	// Values contains the record data (IP addresses, target hostnames, etc.).
	Values []string

	// Zone is the name of the zone this record belongs to.
	Zone string

	// Source indicates where this record came from (e.g., "gcp", "zonefile").
	Source string

	// Metadata contains additional provider-specific information.
	Metadata map[string]string

	// FetchedAt is when this record was retrieved.
	FetchedAt time.Time
}

// FQDN returns the fully qualified domain name with a trailing dot.
func (r *Record) FQDN() string {
	if len(r.Name) > 0 && r.Name[len(r.Name)-1] == '.' {
		return r.Name
	}
	return r.Name + "."
}

// Target returns the primary target value for CNAME records or first value for others.
func (r *Record) Target() string {
	if len(r.Values) == 0 {
		return ""
	}
	return r.Values[0]
}

// IsTakeoverCandidate returns true if this record type can be a subdomain takeover vector.
func (r *Record) IsTakeoverCandidate() bool {
	switch r.Type {
	case RecordTypeCNAME, RecordTypeA, RecordTypeAAAA:
		return true
	default:
		return false
	}
}

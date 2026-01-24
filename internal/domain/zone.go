package domain

import "time"

// Zone represents a DNS zone containing multiple records.
type Zone struct {
	// Name is the zone name (e.g., "example.com.").
	Name string

	// Records contains all DNS records in this zone.
	Records []*Record

	// Source indicates where this zone came from (e.g., "gcp", "zonefile").
	Source string

	// SourceID is the provider-specific identifier (e.g., GCP managed zone name).
	SourceID string

	// Metadata contains additional provider-specific information.
	Metadata map[string]string

	// FetchedAt is when this zone was retrieved.
	FetchedAt time.Time
}

// FQDN returns the zone name with a trailing dot.
func (z *Zone) FQDN() string {
	if len(z.Name) > 0 && z.Name[len(z.Name)-1] == '.' {
		return z.Name
	}
	return z.Name + "."
}

// TakeoverCandidates returns records that could be subdomain takeover vectors.
func (z *Zone) TakeoverCandidates() []*Record {
	var candidates []*Record
	for _, r := range z.Records {
		if r.IsTakeoverCandidate() {
			candidates = append(candidates, r)
		}
	}
	return candidates
}

// RecordsByType returns all records of a specific type.
func (z *Zone) RecordsByType(recordType RecordType) []*Record {
	var results []*Record
	for _, r := range z.Records {
		if r.Type == recordType {
			results = append(results, r)
		}
	}
	return results
}

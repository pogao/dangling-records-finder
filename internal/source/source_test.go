package source

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/pogao/dangling-records-finder/internal/domain"
)

func TestZoneFileSource_FetchRecords(t *testing.T) {
	// Create a temporary zone file
	content := `$ORIGIN example.com.
$TTL 300

@       IN  SOA     ns1.example.com. admin.example.com. (
                    2024010101  ; serial
                    3600        ; refresh
                    900         ; retry
                    604800      ; expire
                    300         ; minimum
)

@       IN  NS      ns1.example.com.
@       IN  NS      ns2.example.com.

@       IN  A       192.0.2.1
www     IN  A       192.0.2.2
mail    IN  A       192.0.2.3

; CNAME records - potential takeover candidates
cdn     IN  CNAME   d123456.cloudfront.net.
static  IN  CNAME   mybucket.s3.amazonaws.com.
blog    IN  CNAME   myapp.herokuapp.com.
docs    IN  CNAME   myorg.github.io.
files   IN  CNAME   myfiles.blob.core.windows.net.

; MX records
@       IN  MX      10 mail.example.com.
`

	tmpDir := t.TempDir()
	zonePath := filepath.Join(tmpDir, "example.com.zone")
	if err := os.WriteFile(zonePath, []byte(content), 0644); err != nil {
		t.Fatalf("Failed to write test zone file: %v", err)
	}

	source := NewZoneFileSource(ZoneFileConfig{
		FilePath: zonePath,
	})

	if source.Name() != "zonefile" {
		t.Errorf("Expected source name 'zonefile', got %q", source.Name())
	}

	zones, err := source.FetchRecords(context.Background())
	if err != nil {
		t.Fatalf("FetchRecords failed: %v", err)
	}

	if len(zones) != 1 {
		t.Fatalf("Expected 1 zone, got %d", len(zones))
	}

	zone := zones[0]
	if zone.Name != "example.com." {
		t.Errorf("Expected zone name 'example.com.', got %q", zone.Name)
	}

	// Check for expected records
	wantCNAMEs := map[string]string{
		"cdn.example.com.":    "d123456.cloudfront.net",
		"static.example.com.": "mybucket.s3.amazonaws.com",
		"blog.example.com.":   "myapp.herokuapp.com",
		"docs.example.com.":   "myorg.github.io",
		"files.example.com.":  "myfiles.blob.core.windows.net",
	}

	gotCNAMEs := make(map[string]string)
	for _, r := range zone.Records {
		if r.Type == domain.RecordTypeCNAME {
			gotCNAMEs[r.Name] = r.Target()
		}
	}

	if diff := cmp.Diff(wantCNAMEs, gotCNAMEs); diff != "" {
		t.Errorf("CNAME records mismatch (-want +got):\n%s", diff)
	}

	// Check takeover candidates
	candidates := zone.TakeoverCandidates()
	// Should include A records and CNAME records
	if len(candidates) < 5 {
		t.Errorf("Expected at least 5 takeover candidates, got %d", len(candidates))
	}
}

func TestZoneFileSource_FetchRecords_MissingFile(t *testing.T) {
	source := NewZoneFileSource(ZoneFileConfig{
		FilePath: "/nonexistent/path/zone.txt",
	})

	_, err := source.FetchRecords(context.Background())
	if err == nil {
		t.Error("Expected error for missing file")
	}
}

func TestZoneFileSource_InferOrigin(t *testing.T) {
	tests := []struct {
		filename string
		want     string
	}{
		{"example.com.zone", "example.com."},
		{"example.com.txt", "example.com."},
		{"example.com", "example.com."},
		{"test.zone", "test."},
	}

	for _, tt := range tests {
		t.Run(tt.filename, func(t *testing.T) {
			source := &ZoneFileSource{filePath: tt.filename}
			got := source.inferOriginFromFilename()
			if got != tt.want {
				t.Errorf("inferOriginFromFilename() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestRecord_IsTakeoverCandidate(t *testing.T) {
	tests := []struct {
		recordType domain.RecordType
		want       bool
	}{
		{domain.RecordTypeCNAME, true},
		{domain.RecordTypeA, true},
		{domain.RecordTypeAAAA, true},
		{domain.RecordTypeMX, false},
		{domain.RecordTypeNS, false},
		{domain.RecordTypeTXT, false},
		{domain.RecordTypeSOA, false},
	}

	for _, tt := range tests {
		t.Run(string(tt.recordType), func(t *testing.T) {
			r := &domain.Record{Type: tt.recordType}
			if got := r.IsTakeoverCandidate(); got != tt.want {
				t.Errorf("IsTakeoverCandidate() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestZone_TakeoverCandidates(t *testing.T) {
	zone := &domain.Zone{
		Name: "example.com.",
		Records: []*domain.Record{
			{Name: "www", Type: domain.RecordTypeA, Values: []string{"192.0.2.1"}},
			{Name: "mail", Type: domain.RecordTypeMX, Values: []string{"10 mail.example.com"}},
			{Name: "cdn", Type: domain.RecordTypeCNAME, Values: []string{"d123.cloudfront.net"}},
			{Name: "ns1", Type: domain.RecordTypeNS, Values: []string{"ns1.example.com"}},
			{Name: "ipv6", Type: domain.RecordTypeAAAA, Values: []string{"2001:db8::1"}},
		},
	}

	candidates := zone.TakeoverCandidates()
	if len(candidates) != 3 {
		t.Errorf("Expected 3 takeover candidates, got %d", len(candidates))
	}

	// Verify the correct types are returned
	types := make(map[domain.RecordType]bool)
	for _, c := range candidates {
		types[c.Type] = true
	}

	wantTypes := map[domain.RecordType]bool{
		domain.RecordTypeA:     true,
		domain.RecordTypeCNAME: true,
		domain.RecordTypeAAAA:  true,
	}

	if diff := cmp.Diff(wantTypes, types, cmpopts.EquateEmpty()); diff != "" {
		t.Errorf("Candidate types mismatch (-want +got):\n%s", diff)
	}
}

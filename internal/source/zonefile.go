package source

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/pogao/dangling-records-finder/internal/domain"
)

// ZoneFileSource parses DNS records from BIND zone files.
type ZoneFileSource struct {
	filePath string
	verbose  bool
}

// ZoneFileConfig contains configuration for the zone file source.
type ZoneFileConfig struct {
	FilePath string
	Verbose  bool
}

// NewZoneFileSource creates a new zone file source.
func NewZoneFileSource(cfg ZoneFileConfig) *ZoneFileSource {
	return &ZoneFileSource{
		filePath: cfg.FilePath,
		verbose:  cfg.Verbose,
	}
}

// Name returns the source identifier.
func (z *ZoneFileSource) Name() string {
	return "zonefile"
}

// FetchRecords parses the zone file and returns DNS records.
func (z *ZoneFileSource) FetchRecords(ctx context.Context) ([]*domain.Zone, error) {
	file, err := os.Open(z.filePath)
	if err != nil {
		return nil, domain.NewSourceError(z.Name(), "open file", err)
	}
	defer file.Close()

	// Try to determine origin from filename if not specified in file
	defaultOrigin := z.inferOriginFromFilename()

	zone := &domain.Zone{
		Name:      defaultOrigin,
		Source:    z.Name(),
		SourceID:  z.filePath,
		FetchedAt: time.Now().UTC(),
		Metadata: map[string]string{
			"filepath": z.filePath,
		},
	}

	// Parse the zone file using miekg/dns
	zp := dns.NewZoneParser(bufio.NewReader(file), defaultOrigin, z.filePath)

	for rr, ok := zp.Next(); ok; rr, ok = zp.Next() {
		record := z.convertRR(rr, zone.Name)
		if record != nil {
			zone.Records = append(zone.Records, record)
		}
	}

	if err := zp.Err(); err != nil {
		return nil, domain.NewSourceError(z.Name(), "parse zone file", err)
	}

	// Update zone name if we found an SOA record
	for _, r := range zone.Records {
		if r.Type == domain.RecordTypeSOA {
			zone.Name = r.Name
			break
		}
	}

	return []*domain.Zone{zone}, nil
}

func (z *ZoneFileSource) inferOriginFromFilename() string {
	base := filepath.Base(z.filePath)
	// Remove common extensions
	for _, ext := range []string{".zone", ".txt", ".db"} {
		base = strings.TrimSuffix(base, ext)
	}
	// Ensure trailing dot for FQDN
	if !strings.HasSuffix(base, ".") {
		base += "."
	}
	return base
}

func (z *ZoneFileSource) convertRR(rr dns.RR, zoneName string) *domain.Record {
	header := rr.Header()
	fetchTime := time.Now().UTC()

	record := &domain.Record{
		Name:      header.Name,
		TTL:       header.Ttl,
		Zone:      zoneName,
		Source:    z.Name(),
		FetchedAt: fetchTime,
		Metadata:  make(map[string]string),
	}

	switch v := rr.(type) {
	case *dns.A:
		record.Type = domain.RecordTypeA
		record.Values = []string{v.A.String()}
	case *dns.AAAA:
		record.Type = domain.RecordTypeAAAA
		record.Values = []string{v.AAAA.String()}
	case *dns.CNAME:
		record.Type = domain.RecordTypeCNAME
		// Remove trailing dot from target for consistency
		record.Values = []string{strings.TrimSuffix(v.Target, ".")}
	case *dns.MX:
		record.Type = domain.RecordTypeMX
		record.Values = []string{fmt.Sprintf("%d %s", v.Preference, strings.TrimSuffix(v.Mx, "."))}
	case *dns.NS:
		record.Type = domain.RecordTypeNS
		record.Values = []string{strings.TrimSuffix(v.Ns, ".")}
	case *dns.TXT:
		record.Type = domain.RecordTypeTXT
		record.Values = v.Txt
	case *dns.SOA:
		record.Type = domain.RecordTypeSOA
		record.Values = []string{fmt.Sprintf("%s %s %d %d %d %d %d",
			v.Ns, v.Mbox, v.Serial, v.Refresh, v.Retry, v.Expire, v.Minttl)}
	case *dns.SRV:
		record.Type = domain.RecordTypeSRV
		record.Values = []string{fmt.Sprintf("%d %d %d %s",
			v.Priority, v.Weight, v.Port, strings.TrimSuffix(v.Target, "."))}
	default:
		// Skip unsupported record types
		return nil
	}

	return record
}

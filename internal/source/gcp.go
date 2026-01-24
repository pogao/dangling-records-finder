package source

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/pogao/dangling-records-finder/internal/domain"
	"google.golang.org/api/dns/v2"
	"google.golang.org/api/googleapi"
)

// GCPSource fetches DNS records from GCP Cloud DNS.
type GCPSource struct {
	projectID string
	location  string
	verbose   bool
}

// GCPConfig contains configuration for the GCP source.
type GCPConfig struct {
	ProjectID string
	Location  string // defaults to "global"
	Verbose   bool
}

// NewGCPSource creates a new GCP Cloud DNS source.
func NewGCPSource(cfg GCPConfig) *GCPSource {
	location := cfg.Location
	if location == "" {
		location = "global"
	}
	return &GCPSource{
		projectID: cfg.ProjectID,
		location:  location,
		verbose:   cfg.Verbose,
	}
}

// Name returns the source identifier.
func (g *GCPSource) Name() string {
	return "gcp"
}

// FetchRecords retrieves all DNS zones and records from GCP Cloud DNS.
func (g *GCPSource) FetchRecords(ctx context.Context) ([]*domain.Zone, error) {
	dnsService, err := dns.NewService(ctx)
	if err != nil {
		return nil, domain.NewSourceError(g.Name(), "create service", err)
	}

	managedZonesService := dns.NewManagedZonesService(dnsService)
	resourceRecordSetsService := dns.NewResourceRecordSetsService(dnsService)

	// List all managed zones
	zonesResp, err := managedZonesService.List(g.projectID, g.location).
		Do(googleapi.QueryParameter("userProject", g.projectID))
	if err != nil {
		return nil, domain.NewSourceError(g.Name(), "list zones", err)
	}

	var zones []*domain.Zone
	fetchTime := time.Now().UTC()

	for _, mz := range zonesResp.ManagedZones {
		zone := &domain.Zone{
			Name:      mz.DnsName,
			Source:    g.Name(),
			SourceID:  mz.Name,
			FetchedAt: fetchTime,
			Metadata: map[string]string{
				"visibility":  mz.Visibility,
				"description": mz.Description,
			},
		}

		// Fetch all record sets for this zone
		if err := g.fetchRecordSets(ctx, resourceRecordSetsService, mz.Name, zone); err != nil {
			return nil, err
		}

		zones = append(zones, zone)
	}

	return zones, nil
}

func (g *GCPSource) fetchRecordSets(ctx context.Context, svc *dns.ResourceRecordSetsService, zoneName string, zone *domain.Zone) error {
	var pageToken string
	fetchTime := time.Now().UTC()

	for {
		call := svc.List(g.projectID, g.location, zoneName)
		if pageToken != "" {
			call = call.PageToken(pageToken)
		}

		resp, err := call.Do(googleapi.QueryParameter("userProject", g.projectID))
		if err != nil {
			return domain.NewSourceError(g.Name(), fmt.Sprintf("list records for zone %s", zoneName), err)
		}

		for _, rrs := range resp.Rrsets {
			recordType := domain.RecordType(rrs.Type)
			record := &domain.Record{
				Name:      rrs.Name,
				Type:      recordType,
				TTL:       uint32(rrs.Ttl),
				Values:    rrs.Rrdatas,
				Zone:      zone.Name,
				Source:    g.Name(),
				FetchedAt: fetchTime,
				Metadata:  make(map[string]string),
			}

			// Clean up CNAME targets (remove trailing dots for consistency)
			if recordType == domain.RecordTypeCNAME && len(record.Values) > 0 {
				record.Values[0] = strings.TrimSuffix(record.Values[0], ".")
			}

			zone.Records = append(zone.Records, record)
		}

		pageToken = resp.NextPageToken
		if pageToken == "" {
			break
		}
	}

	return nil
}

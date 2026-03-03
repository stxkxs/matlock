package gcp

import (
	"context"
	"fmt"
	"math"
	"os"
	"time"

	"google.golang.org/api/certificatemanager/v1"

	"github.com/stxkxs/matlock/internal/cloud"
)

// ListCertificates returns GCP Certificate Manager certificates expiring within 180 days.
func (p *Provider) ListCertificates(ctx context.Context) ([]cloud.CertFinding, error) {
	if p.projectID == "" {
		return nil, fmt.Errorf("GCP project ID is required")
	}
	svc, err := certificatemanager.NewService(ctx, p.opts...)
	if err != nil {
		return nil, fmt.Errorf("certificate manager client: %w", err)
	}

	now := time.Now()
	var findings []cloud.CertFinding

	parent := fmt.Sprintf("projects/%s/locations/-", p.projectID)
	req := svc.Projects.Locations.Certificates.List(parent)
	if err := req.Pages(ctx, func(page *certificatemanager.ListCertificatesResponse) error {
		for _, cert := range page.Certificates {
			if cert.ExpireTime == "" {
				continue
			}
			expiry, err := time.Parse(time.RFC3339, cert.ExpireTime)
			if err != nil {
				continue
			}
			daysLeft := int(math.Floor(expiry.Sub(now).Hours() / 24))
			if daysLeft > 180 {
				continue
			}
			sev, status := cloud.CertSeverity(daysLeft)
			domain := cert.Name
			// Extract short name from full resource name
			if idx := lastSlash(cert.Name); idx >= 0 {
				domain = cert.Name[idx+1:]
			}
			findings = append(findings, cloud.CertFinding{
				Severity:  sev,
				Status:    status,
				Provider:  "gcp",
				Domain:    domain,
				ARN:       cert.Name,
				ExpiresAt: expiry,
				DaysLeft:  daysLeft,
				Detail:    fmt.Sprintf("certificate %s expires in %d days", domain, daysLeft),
			})
		}
		return nil
	}); err != nil {
		// Certificate Manager API may not be enabled — warn and return empty
		fmt.Fprintf(os.Stderr, "warn: gcp certificate manager: %v (API may not be enabled)\n", err)
		return nil, nil
	}
	return findings, nil
}

func lastSlash(s string) int {
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] == '/' {
			return i
		}
	}
	return -1
}

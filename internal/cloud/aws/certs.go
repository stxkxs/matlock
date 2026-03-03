package aws

import (
	"context"
	"fmt"
	"math"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/acm"
	acmtypes "github.com/aws/aws-sdk-go-v2/service/acm/types"
	"github.com/stxkxs/matlock/internal/cloud"
)

// ListCertificates returns ACM certificates expiring within 180 days or already expired.
func (p *Provider) ListCertificates(ctx context.Context) ([]cloud.CertFinding, error) {
	client := acm.NewFromConfig(p.cfg)
	pager := acm.NewListCertificatesPaginator(client, &acm.ListCertificatesInput{
		CertificateStatuses: []acmtypes.CertificateStatus{acmtypes.CertificateStatusIssued},
	})

	now := time.Now()
	var findings []cloud.CertFinding

	for pager.HasMorePages() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("list certificates: %w", err)
		}
		for _, summary := range page.CertificateSummaryList {
			arn := awssdk.ToString(summary.CertificateArn)
			detail, err := client.DescribeCertificate(ctx, &acm.DescribeCertificateInput{
				CertificateArn: awssdk.String(arn),
			})
			if err != nil {
				// Skip certs we can't describe
				continue
			}
			cert := detail.Certificate
			if cert == nil || cert.NotAfter == nil {
				continue
			}

			daysLeft := int(math.Floor(cert.NotAfter.Sub(now).Hours() / 24))
			if daysLeft > 180 {
				continue // outside monitoring window
			}

			sev, status := cloud.CertSeverity(daysLeft)
			domain := awssdk.ToString(cert.DomainName)
			findings = append(findings, cloud.CertFinding{
				Severity:  sev,
				Status:    status,
				Provider:  "aws",
				Domain:    domain,
				ARN:       arn,
				Region:    p.cfg.Region,
				ExpiresAt: *cert.NotAfter,
				DaysLeft:  daysLeft,
				Detail:    fmt.Sprintf("certificate for %s expires in %d days", domain, daysLeft),
			})
		}
	}
	return findings, nil
}

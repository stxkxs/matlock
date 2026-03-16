package gcp

import (
	"context"
	"fmt"

	"github.com/stxkxs/matlock/internal/cloud"
	"google.golang.org/api/compute/v1"
	adminv1 "google.golang.org/api/iam/v1"
)

// ListQuotas returns project-level quota utilization from Compute Engine and IAM.
func (p *Provider) ListQuotas(ctx context.Context) ([]cloud.QuotaUsage, error) {
	if p.projectID == "" {
		return nil, fmt.Errorf("GOOGLE_CLOUD_PROJECT not set")
	}

	var quotas []cloud.QuotaUsage

	computeQuotas, err := p.computeQuotas(ctx)
	if err != nil {
		return nil, fmt.Errorf("compute quotas: %w", err)
	}
	quotas = append(quotas, computeQuotas...)

	iamQuotas, err := p.iamServiceAccountQuotas(ctx)
	if err != nil {
		return nil, fmt.Errorf("iam quotas: %w", err)
	}
	quotas = append(quotas, iamQuotas...)

	return quotas, nil
}

func (p *Provider) computeQuotas(ctx context.Context) ([]cloud.QuotaUsage, error) {
	svc, err := compute.NewService(ctx, p.opts...)
	if err != nil {
		return nil, fmt.Errorf("create compute service: %w", err)
	}

	project, err := svc.Projects.Get(p.projectID).Context(ctx).Do()
	if err != nil {
		return nil, fmt.Errorf("get project: %w", err)
	}

	var quotas []cloud.QuotaUsage
	for _, q := range project.Quotas {
		if q.Limit <= 0 {
			continue
		}
		utilization := q.Usage / q.Limit * 100
		quotas = append(quotas, cloud.QuotaUsage{
			Provider:    "gcp",
			Service:     "Compute",
			QuotaName:   q.Metric,
			Used:        q.Usage,
			Limit:       q.Limit,
			Utilization: utilization,
			Region:      "project",
		})
	}
	return quotas, nil
}

func (p *Provider) iamServiceAccountQuotas(ctx context.Context) ([]cloud.QuotaUsage, error) {
	svc, err := adminv1.NewService(ctx, p.opts...)
	if err != nil {
		return nil, fmt.Errorf("create iam service: %w", err)
	}

	resp, err := svc.Projects.ServiceAccounts.List("projects/" + p.projectID).Context(ctx).Do()
	if err != nil {
		return nil, fmt.Errorf("list service accounts: %w", err)
	}

	used := float64(len(resp.Accounts))
	limit := float64(100) // Default GCP service account limit per project

	return []cloud.QuotaUsage{{
		Provider:    "gcp",
		Service:     "IAM",
		QuotaName:   "Service Accounts",
		Used:        used,
		Limit:       limit,
		Utilization: pctGCP(used, limit),
		Region:      "project",
	}}, nil
}

func pctGCP(used, limit float64) float64 {
	if limit == 0 {
		return 0
	}
	return used / limit * 100
}

// compile-time check
var _ cloud.QuotaProvider = (*Provider)(nil)

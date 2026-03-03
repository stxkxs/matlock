package gcp

import (
	"context"
	"fmt"

	"google.golang.org/api/compute/v1"

	"github.com/stxkxs/matlock/internal/cloud"
)

// ListOrphans returns unused GCP compute resources.
func (p *Provider) ListOrphans(ctx context.Context) ([]cloud.OrphanResource, error) {
	svc, err := compute.NewService(ctx, p.opts...)
	if err != nil {
		return nil, fmt.Errorf("compute client: %w", err)
	}

	var orphans []cloud.OrphanResource

	disks, err := p.orphanDisks(ctx, svc)
	if err != nil {
		return nil, err
	}
	orphans = append(orphans, disks...)

	ips, err := p.orphanIPs(ctx, svc)
	if err != nil {
		return nil, err
	}
	orphans = append(orphans, ips...)

	return orphans, nil
}

func (p *Provider) orphanDisks(ctx context.Context, svc *compute.Service) ([]cloud.OrphanResource, error) {
	var orphans []cloud.OrphanResource
	if err := svc.Disks.AggregatedList(p.projectID).
		Filter("status=READY").
		Pages(ctx, func(page *compute.DiskAggregatedList) error {
			for _, items := range page.Items {
				for _, disk := range items.Disks {
					if len(disk.Users) > 0 {
						continue // disk is attached
					}
					cost := float64(disk.SizeGb) * 0.04 // ~$0.04/GB-month for pd-standard
					orphans = append(orphans, cloud.OrphanResource{
						Kind:        cloud.OrphanDisk,
						ID:          fmt.Sprintf("%d", disk.Id),
						Name:        disk.Name,
						Region:      disk.Zone,
						Provider:    "gcp",
						MonthlyCost: cost,
						Detail:      fmt.Sprintf("%d GiB %s, no users", disk.SizeGb, disk.Type),
					})
				}
			}
			return nil
		}); err != nil {
		return nil, fmt.Errorf("list disks: %w", err)
	}
	return orphans, nil
}

func (p *Provider) orphanIPs(ctx context.Context, svc *compute.Service) ([]cloud.OrphanResource, error) {
	var orphans []cloud.OrphanResource
	if err := svc.Addresses.AggregatedList(p.projectID).
		Filter("status=RESERVED").
		Pages(ctx, func(page *compute.AddressAggregatedList) error {
			for _, items := range page.Items {
				for _, addr := range items.Addresses {
					if addr.Users != nil && len(addr.Users) > 0 {
						continue
					}
					orphans = append(orphans, cloud.OrphanResource{
						Kind:        cloud.OrphanIP,
						ID:          fmt.Sprintf("%d", addr.Id),
						Name:        addr.Address,
						Region:      addr.Region,
						Provider:    "gcp",
						MonthlyCost: 1.46, // ~$0.002/hr for unused static IP
						Detail:      fmt.Sprintf("static IP %s is reserved but unassigned", addr.Address),
					})
				}
			}
			return nil
		}); err != nil {
		return nil, fmt.Errorf("list addresses: %w", err)
	}
	return orphans, nil
}

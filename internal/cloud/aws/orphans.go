package aws

import (
	"context"
	"fmt"
	"os"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"
	"github.com/stxkxs/matlock/internal/cloud"
)

// ListOrphans returns unused AWS resources across the configured region.
func (p *Provider) ListOrphans(ctx context.Context) ([]cloud.OrphanResource, error) {
	var orphans []cloud.OrphanResource

	disks, err := p.orphanDisks(ctx)
	if err != nil {
		return nil, fmt.Errorf("orphan disks: %w", err)
	}
	orphans = append(orphans, disks...)

	ips, err := p.orphanIPs(ctx)
	if err != nil {
		return nil, fmt.Errorf("orphan IPs: %w", err)
	}
	orphans = append(orphans, ips...)

	lbs, err := p.orphanLoadBalancers(ctx)
	if err != nil {
		return nil, fmt.Errorf("orphan load balancers: %w", err)
	}
	orphans = append(orphans, lbs...)

	return orphans, nil
}

// orphanDisks finds EBS volumes that are not attached to any instance.
func (p *Provider) orphanDisks(ctx context.Context) ([]cloud.OrphanResource, error) {
	client := ec2.NewFromConfig(p.cfg)
	pager := ec2.NewDescribeVolumesPaginator(client, &ec2.DescribeVolumesInput{
		Filters: []ec2types.Filter{{
			Name:   awssdk.String("status"),
			Values: []string{"available"},
		}},
	})

	var orphans []cloud.OrphanResource
	for pager.HasMorePages() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			fmt.Fprintf(os.Stderr, "warn: describe volumes page: %v\n", err)
			break
		}
		for _, v := range page.Volumes {
			name := volumeName(v)
			sizeGB := int32(0)
			if v.Size != nil {
				sizeGB = *v.Size
			}
			// Rough cost estimate: $0.10/GB-month for gp2/gp3
			cost := float64(sizeGB) * 0.10
			orphans = append(orphans, cloud.OrphanResource{
				Kind:        cloud.OrphanDisk,
				ID:          awssdk.ToString(v.VolumeId),
				Name:        name,
				Region:      p.cfg.Region,
				Provider:    "aws",
				MonthlyCost: cost,
				Detail:      fmt.Sprintf("%d GiB %s, state: available", sizeGB, v.VolumeType),
			})
		}
	}
	return orphans, nil
}

func volumeName(v ec2types.Volume) string {
	for _, tag := range v.Tags {
		if awssdk.ToString(tag.Key) == "Name" {
			return awssdk.ToString(tag.Value)
		}
	}
	return awssdk.ToString(v.VolumeId)
}

// orphanIPs finds Elastic IPs that are not associated with any resource.
func (p *Provider) orphanIPs(ctx context.Context) ([]cloud.OrphanResource, error) {
	client := ec2.NewFromConfig(p.cfg)
	out, err := client.DescribeAddresses(ctx, &ec2.DescribeAddressesInput{})
	if err != nil {
		return nil, err
	}

	var orphans []cloud.OrphanResource
	for _, addr := range out.Addresses {
		if addr.AssociationId != nil {
			continue // in use
		}
		orphans = append(orphans, cloud.OrphanResource{
			Kind:        cloud.OrphanIP,
			ID:          awssdk.ToString(addr.AllocationId),
			Name:        awssdk.ToString(addr.PublicIp),
			Region:      p.cfg.Region,
			Provider:    "aws",
			MonthlyCost: 3.65, // ~$0.005/hr for unassociated EIPs
			Detail:      fmt.Sprintf("EIP %s is unassociated", awssdk.ToString(addr.PublicIp)),
		})
	}
	return orphans, nil
}

// orphanLoadBalancers finds ALBs/NLBs with no registered targets.
func (p *Provider) orphanLoadBalancers(ctx context.Context) ([]cloud.OrphanResource, error) {
	client := elasticloadbalancingv2.NewFromConfig(p.cfg)

	lbPager := elasticloadbalancingv2.NewDescribeLoadBalancersPaginator(client, &elasticloadbalancingv2.DescribeLoadBalancersInput{})
	var orphans []cloud.OrphanResource

	for lbPager.HasMorePages() {
		page, err := lbPager.NextPage(ctx)
		if err != nil {
			fmt.Fprintf(os.Stderr, "warn: describe load balancers page: %v\n", err)
			break
		}
		for _, lb := range page.LoadBalancers {
			if lb.LoadBalancerArn == nil {
				continue
			}
			empty, err := p.lbHasNoTargets(ctx, client, awssdk.ToString(lb.LoadBalancerArn))
			if err != nil || !empty {
				continue
			}
			orphans = append(orphans, cloud.OrphanResource{
				Kind:        cloud.OrphanLoadBalancer,
				ID:          awssdk.ToString(lb.LoadBalancerArn),
				Name:        awssdk.ToString(lb.LoadBalancerName),
				Region:      p.cfg.Region,
				Provider:    "aws",
				MonthlyCost: 16.43, // ~$0.022/hr base ALB charge
				Detail:      fmt.Sprintf("%s has no registered targets", lb.Type),
			})
		}
	}
	return orphans, nil
}

func (p *Provider) lbHasNoTargets(ctx context.Context, client *elasticloadbalancingv2.Client, lbArn string) (bool, error) {
	out, err := client.DescribeTargetGroups(ctx, &elasticloadbalancingv2.DescribeTargetGroupsInput{
		LoadBalancerArn: awssdk.String(lbArn),
	})
	if err != nil {
		return false, err
	}
	if len(out.TargetGroups) == 0 {
		return true, nil
	}
	for _, tg := range out.TargetGroups {
		health, err := client.DescribeTargetHealth(ctx, &elasticloadbalancingv2.DescribeTargetHealthInput{
			TargetGroupArn: tg.TargetGroupArn,
		})
		if err != nil {
			continue
		}
		if len(health.TargetHealthDescriptions) > 0 {
			return false, nil
		}
	}
	return true, nil
}

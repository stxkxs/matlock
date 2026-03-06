package aws

import (
	"context"
	"fmt"
	"strings"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/stxkxs/matlock/internal/cloud"
)

// ListResources lists AWS resources for inventory.
func (p *Provider) ListResources(ctx context.Context, typeFilter []string) ([]cloud.InventoryResource, error) {
	filter := make(map[string]bool)
	for _, t := range typeFilter {
		filter[strings.ToLower(t)] = true
	}
	all := len(filter) == 0

	var resources []cloud.InventoryResource

	if all || filter["ec2"] || filter["ec2:instance"] {
		r, err := p.listEC2Instances(ctx)
		if err != nil {
			return nil, fmt.Errorf("list ec2 instances: %w", err)
		}
		resources = append(resources, r...)
	}

	if all || filter["s3"] || filter["s3:bucket"] {
		r, err := p.listS3Buckets(ctx)
		if err != nil {
			return nil, fmt.Errorf("list s3 buckets: %w", err)
		}
		resources = append(resources, r...)
	}

	if all || filter["lambda"] || filter["lambda:function"] {
		r, err := p.listLambdaFunctions(ctx)
		if err != nil {
			return nil, fmt.Errorf("list lambda functions: %w", err)
		}
		resources = append(resources, r...)
	}

	if all || filter["ebs"] || filter["ebs:volume"] {
		r, err := p.listEBSVolumes(ctx)
		if err != nil {
			return nil, fmt.Errorf("list ebs volumes: %w", err)
		}
		resources = append(resources, r...)
	}

	return resources, nil
}

func (p *Provider) listEC2Instances(ctx context.Context) ([]cloud.InventoryResource, error) {
	client := ec2.NewFromConfig(p.cfg)
	var resources []cloud.InventoryResource

	paginator := ec2.NewDescribeInstancesPaginator(client, &ec2.DescribeInstancesInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return resources, fmt.Errorf("describe instances: %w", err)
		}
		for _, res := range page.Reservations {
			for _, inst := range res.Instances {
				name := ec2TagValue(inst.Tags, "Name")
				id := awssdk.ToString(inst.InstanceId)
				status := string(inst.State.Name)
				tags := ec2TagsToMap(inst.Tags)
				r := cloud.InventoryResource{
					Kind:     cloud.ResourceCompute,
					Type:     "ec2:instance",
					ID:       id,
					Name:     name,
					Provider: "aws",
					Region:   p.cfg.Region,
					Tags:     tags,
					Status:   status,
				}
				if inst.LaunchTime != nil {
					t := *inst.LaunchTime
					r.CreatedAt = &t
				}
				resources = append(resources, r)
			}
		}
	}
	return resources, nil
}

func (p *Provider) listS3Buckets(ctx context.Context) ([]cloud.InventoryResource, error) {
	client := s3.NewFromConfig(p.cfg)
	out, err := client.ListBuckets(ctx, &s3.ListBucketsInput{})
	if err != nil {
		return nil, fmt.Errorf("list buckets: %w", err)
	}

	var resources []cloud.InventoryResource
	for _, b := range out.Buckets {
		name := awssdk.ToString(b.Name)
		r := cloud.InventoryResource{
			Kind:     cloud.ResourceStorage,
			Type:     "s3:bucket",
			ID:       name,
			Name:     name,
			Provider: "aws",
			Region:   p.cfg.Region,
		}
		if b.CreationDate != nil {
			t := *b.CreationDate
			r.CreatedAt = &t
		}
		resources = append(resources, r)
	}
	return resources, nil
}

func (p *Provider) listLambdaFunctions(ctx context.Context) ([]cloud.InventoryResource, error) {
	client := lambda.NewFromConfig(p.cfg)
	var resources []cloud.InventoryResource

	var marker *string
	for {
		out, err := client.ListFunctions(ctx, &lambda.ListFunctionsInput{Marker: marker})
		if err != nil {
			return resources, fmt.Errorf("list functions: %w", err)
		}
		for _, fn := range out.Functions {
			name := awssdk.ToString(fn.FunctionName)
			resources = append(resources, cloud.InventoryResource{
				Kind:     cloud.ResourceServerless,
				Type:     "lambda:function",
				ID:       awssdk.ToString(fn.FunctionArn),
				Name:     name,
				Provider: "aws",
				Region:   p.cfg.Region,
				Status:   string(fn.State),
			})
		}
		if out.NextMarker == nil {
			break
		}
		marker = out.NextMarker
	}
	return resources, nil
}

func (p *Provider) listEBSVolumes(ctx context.Context) ([]cloud.InventoryResource, error) {
	client := ec2.NewFromConfig(p.cfg)
	var resources []cloud.InventoryResource

	paginator := ec2.NewDescribeVolumesPaginator(client, &ec2.DescribeVolumesInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return resources, fmt.Errorf("describe volumes: %w", err)
		}
		for _, vol := range page.Volumes {
			name := ec2TagValue(vol.Tags, "Name")
			id := awssdk.ToString(vol.VolumeId)
			r := cloud.InventoryResource{
				Kind:     cloud.ResourceStorage,
				Type:     "ebs:volume",
				ID:       id,
				Name:     name,
				Provider: "aws",
				Region:   p.cfg.Region,
				Tags:     ec2TagsToMap(vol.Tags),
				Status:   string(vol.State),
			}
			if vol.CreateTime != nil {
				t := *vol.CreateTime
				r.CreatedAt = &t
			}
			resources = append(resources, r)
		}
	}
	return resources, nil
}

func ec2TagValue(tags []ec2types.Tag, key string) string {
	for _, t := range tags {
		if awssdk.ToString(t.Key) == key {
			return awssdk.ToString(t.Value)
		}
	}
	return ""
}

func ec2TagsToMap(tags []ec2types.Tag) map[string]string {
	if len(tags) == 0 {
		return nil
	}
	m := make(map[string]string, len(tags))
	for _, t := range tags {
		m[awssdk.ToString(t.Key)] = awssdk.ToString(t.Value)
	}
	return m
}

package gcp

import (
	"context"
	"fmt"

	compute "google.golang.org/api/compute/v1"
	cloudfunctions "google.golang.org/api/cloudfunctions/v1"
	run "google.golang.org/api/run/v1"

	"github.com/stxkxs/matlock/internal/cloud"
	"github.com/stxkxs/matlock/internal/secrets"
)

// ScanSecrets checks Cloud Functions env, Cloud Run env, and Compute startup scripts for secrets.
func (p *Provider) ScanSecrets(ctx context.Context) ([]cloud.SecretFinding, error) {
	var findings []cloud.SecretFinding

	if f, err := p.scanCloudFunctionSecrets(ctx); err != nil {
		return nil, fmt.Errorf("cloud functions secrets: %w", err)
	} else {
		findings = append(findings, f...)
	}

	if f, err := p.scanCloudRunSecrets(ctx); err != nil {
		return nil, fmt.Errorf("cloud run secrets: %w", err)
	} else {
		findings = append(findings, f...)
	}

	if f, err := p.scanComputeSecrets(ctx); err != nil {
		return nil, fmt.Errorf("compute secrets: %w", err)
	} else {
		findings = append(findings, f...)
	}

	return findings, nil
}

func (p *Provider) scanCloudFunctionSecrets(ctx context.Context) ([]cloud.SecretFinding, error) {
	svc, err := cloudfunctions.NewService(ctx, p.opts...)
	if err != nil {
		return nil, fmt.Errorf("create cloud functions client: %w", err)
	}

	var findings []cloud.SecretFinding
	parent := fmt.Sprintf("projects/%s/locations/-", p.projectID)
	if err := svc.Projects.Locations.Functions.List(parent).Pages(ctx, func(resp *cloudfunctions.ListFunctionsResponse) error {
		for _, fn := range resp.Functions {
			envVars := fn.EnvironmentVariables
			if len(envVars) == 0 {
				continue
			}
			for key, val := range envVars {
				for _, m := range secrets.Scan(val) {
					findings = append(findings, cloud.SecretFinding{
						Severity:     m.Severity,
						Type:         m.Type,
						Provider:     "gcp",
						Resource:     "cloud-function:" + fn.Name,
						ResourceType: "cloud_function_env",
						Region:       "",
						Key:          key,
						Match:        secrets.Redact(m.Value),
						Detail:       fmt.Sprintf("%s found in Cloud Function %q env var %q", m.Name, fn.Name, key),
						Remediation:  fmt.Sprintf("Move secret from env var %q to Secret Manager", key),
					})
				}
			}
		}
		return nil
	}); err != nil {
		return findings, fmt.Errorf("list functions: %w", err)
	}
	return findings, nil
}

func (p *Provider) scanCloudRunSecrets(ctx context.Context) ([]cloud.SecretFinding, error) {
	svc, err := run.NewService(ctx, p.opts...)
	if err != nil {
		return nil, fmt.Errorf("create cloud run client: %w", err)
	}

	var findings []cloud.SecretFinding
	parent := fmt.Sprintf("namespaces/%s", p.projectID)
	resp, err := svc.Namespaces.Services.List(parent).Context(ctx).Do()
	if err != nil {
		return nil, fmt.Errorf("list cloud run services: %w", err)
	}

	for _, service := range resp.Items {
		if service.Spec == nil || service.Spec.Template == nil || service.Spec.Template.Spec == nil {
			continue
		}
		for _, container := range service.Spec.Template.Spec.Containers {
			for _, env := range container.Env {
				if env.Value == "" {
					continue
				}
				for _, m := range secrets.Scan(env.Value) {
					findings = append(findings, cloud.SecretFinding{
						Severity:     m.Severity,
						Type:         m.Type,
						Provider:     "gcp",
						Resource:     "cloud-run:" + service.Metadata.Name,
						ResourceType: "cloud_run_env",
						Region:       "",
						Key:          env.Name,
						Match:        secrets.Redact(m.Value),
						Detail:       fmt.Sprintf("%s found in Cloud Run service %q env var %q", m.Name, service.Metadata.Name, env.Name),
						Remediation:  fmt.Sprintf("Move secret from env var %q to Secret Manager and use secret volume mount", env.Name),
					})
				}
			}
		}
	}
	return findings, nil
}

func (p *Provider) scanComputeSecrets(ctx context.Context) ([]cloud.SecretFinding, error) {
	svc, err := compute.NewService(ctx, p.opts...)
	if err != nil {
		return nil, fmt.Errorf("create compute client: %w", err)
	}

	var findings []cloud.SecretFinding
	if err := svc.Instances.AggregatedList(p.projectID).Pages(ctx, func(list *compute.InstanceAggregatedList) error {
		for _, items := range list.Items {
			for _, inst := range items.Instances {
				// Check startup-script metadata
				if inst.Metadata == nil {
					continue
				}
				for _, item := range inst.Metadata.Items {
					if item.Value == nil {
						continue
					}
					val := *item.Value
					for _, m := range secrets.Scan(val) {
						findings = append(findings, cloud.SecretFinding{
							Severity:     m.Severity,
							Type:         m.Type,
							Provider:     "gcp",
							Resource:     "compute:" + inst.Name,
							ResourceType: "compute_metadata",
							Region:       inst.Zone,
							Key:          item.Key,
							Match:        secrets.Redact(m.Value),
							Detail:       fmt.Sprintf("%s found in Compute instance %q metadata key %q", m.Name, inst.Name, item.Key),
							Remediation:  "Remove secrets from instance metadata; use Secret Manager with appropriate IAM bindings",
						})
					}
				}
			}
		}
		return nil
	}); err != nil {
		return findings, fmt.Errorf("list instances: %w", err)
	}
	return findings, nil
}

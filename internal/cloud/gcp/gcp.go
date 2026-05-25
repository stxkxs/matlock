package gcp

import (
	"context"
	"fmt"
	"os"

	"google.golang.org/api/cloudresourcemanager/v1"
	googleiam "google.golang.org/api/iam/v1"
	"google.golang.org/api/option"
)

// Provider implements Matlock provider interfaces for GCP.
//
// The GCP Go SDK exposes chained call builders (svc.Projects.GetIamPolicy(...).Context(ctx).Do())
// that are awkward to mock directly. We hide that behind narrow per-domain
// interfaces (crmAPI, googleIAMAPI, etc.) declared in their owning files;
// production code wires adapters that wrap the real services, tests inject
// mocks satisfying the same interfaces.
type Provider struct {
	projectID string
	opts      []option.ClientOption
	crm       crmAPI
	googleIAM googleIAMAPI
}

// New creates a GCP provider using Application Default Credentials.
// projectID can be set explicitly; if empty it is read from GOOGLE_CLOUD_PROJECT.
func New(ctx context.Context, projectID string) (*Provider, error) {
	if projectID == "" {
		projectID = os.Getenv("GOOGLE_CLOUD_PROJECT")
		if projectID == "" {
			projectID = os.Getenv("GCLOUD_PROJECT")
		}
	}
	p := &Provider{projectID: projectID}

	crmSvc, err := cloudresourcemanager.NewService(ctx, p.opts...)
	if err != nil {
		return nil, fmt.Errorf("cloudresourcemanager client: %w", err)
	}
	p.crm = &crmAdapter{svc: crmSvc}

	iamSvc, err := googleiam.NewService(ctx, option.WithScopes("https://www.googleapis.com/auth/cloud-platform"))
	if err != nil {
		return nil, fmt.Errorf("iam client: %w", err)
	}
	p.googleIAM = &googleIAMAdapter{svc: iamSvc}

	return p, nil
}

// Name returns the provider identifier.
func (p *Provider) Name() string { return "gcp" }

// Detect returns true when GCP credentials are present in the environment.
func (p *Provider) Detect(_ context.Context) bool {
	if os.Getenv("GOOGLE_APPLICATION_CREDENTIALS") != "" {
		return true
	}
	if os.Getenv("GOOGLE_CLOUD_PROJECT") != "" || os.Getenv("GCLOUD_PROJECT") != "" {
		return true
	}
	home, _ := os.UserHomeDir()
	if home != "" {
		adc := home + "/.config/gcloud/application_default_credentials.json"
		if _, err := os.Stat(adc); err == nil {
			return true
		}
	}
	return false
}

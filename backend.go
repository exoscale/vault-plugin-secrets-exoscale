package exoscale

import (
	"context"
	"fmt"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"

	egoscale "github.com/exoscale/egoscale/v2"
	"github.com/exoscale/vault-plugin-secrets-exoscale/version"
)

const backendHelp = `
The Exoscale secrets backend for Vault dynamically manages Exoscale IAM API
keys based on role-based policies.
`

type exoscaleClient interface {
	CreateIAMAccessKey(context.Context, string, string, ...egoscale.CreateIAMAccessKeyOpt) (*egoscale.IAMAccessKey, error)
	RevokeIAMAccessKey(context.Context, string, *egoscale.IAMAccessKey) error
}

type exoscaleBackend struct {
	exo exoscaleClient
	*framework.Backend
}

func Factory(ctx context.Context, config *logical.BackendConfig) (logical.Backend, error) {
	egoscale.UserAgent = fmt.Sprintf("Exoscale-Vault-Plugin-Secrets/%s (%s) %s",
		version.Version,
		version.Commit,
		egoscale.UserAgent)

	var backend exoscaleBackend

	backend.Backend = &framework.Backend{
		BackendType: logical.TypeLogical,
		Help:        backendHelp,

		Paths: []*framework.Path{
			backend.pathInfo(),
			backend.pathConfigRoot(),
			backend.pathConfigLease(),
			backend.pathListRoles(),
			backend.pathRole(),
			backend.pathAPIKey(),
		},

		Secrets: []*framework.Secret{
			backend.secretAPIKey(),
		},
	}

	backendConfig, err := backend.config(ctx, config.StorageView)
	if err != nil {
		return nil, fmt.Errorf("unable to retrieve backend config from storage: %w", err)
	}

	if backendConfig != nil {
		exo, err := egoscale.NewClient(backendConfig.RootAPIKey, backendConfig.RootAPISecret)
		if err != nil {
			return nil, fmt.Errorf("unable to initialize Exoscale client: %w", err)
		}
		backend.exo = exo
	}

	if err := backend.Setup(ctx, config); err != nil {
		return nil, err
	}

	return &backend, nil
}

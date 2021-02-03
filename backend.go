package exoscale

import (
	"context"
	"fmt"

	"github.com/exoscale/egoscale"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	vaultsdkver "github.com/hashicorp/vault/sdk/version"
	"github.com/pkg/errors"

	"github.com/exoscale/vault-plugin-secrets-exoscale/version"
)

var backendHelp = `
The Exoscale secrets backend for Vault dynamically manages Exoscale IAM API
keys based on role-based policies.
`

type exoscaleBackend struct {
	exo *egoscale.Client
	*framework.Backend
}

func init() {
	egoscale.UserAgent = fmt.Sprintf("Exoscale-Vault-Plugin-Secrets/%s (%s) Vault-SDK/%s %s",
		version.Version,
		version.Commit,
		vaultsdkver.Version,
		egoscale.UserAgent)
}

func Factory(ctx context.Context, config *logical.BackendConfig) (logical.Backend, error) {
	var backend exoscaleBackend

	backend.Backend = &framework.Backend{
		BackendType: logical.TypeLogical,
		Help:        backendHelp,

		Paths: []*framework.Path{
			pathInfo(&backend),
			pathConfigRoot(&backend),
			pathConfigLease(&backend),
			pathListRoles(&backend),
			pathRole(&backend),
			pathAPIKey(&backend),
		},

		Secrets: []*framework.Secret{
			secretAPIKey(&backend),
		},
	}

	backendConfig, err := backend.backendConfig(ctx, config.StorageView)
	if err != nil {
		return nil, errors.Wrap(err, "failed to fetch backend config from storage")
	}
	if backendConfig != nil {
		backend.exo = egoscale.NewClient(backendConfig.APIEndpoint, backendConfig.RootAPIKey, backendConfig.RootAPISecret)
	}

	if err := backend.Setup(ctx, config); err != nil {
		return nil, errors.Wrap(err, "failed to create factory")
	}

	return &backend, nil
}

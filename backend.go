package exoscale

import (
	"context"
	"fmt"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"

	egoscale "github.com/exoscale/egoscale/v2"
	"github.com/exoscale/vault-plugin-secrets-exoscale/version"
)

type exoscaleBackend struct {
	exo *exoscale
	*framework.Backend
}

func Factory(ctx context.Context, config *logical.BackendConfig) (logical.Backend, error) {
	egoscale.UserAgent = fmt.Sprintf("Exoscale-Vault-Plugin-Secrets/%s (%s) %s",
		version.Version, version.Commit, egoscale.UserAgent)

	var backend exoscaleBackend
	backend.Backend = &framework.Backend{
		BackendType: logical.TypeLogical,
		Help:        "Dynamically create Exoscale IAM API Keys",
		Paths: []*framework.Path{
			backend.pathInfo(),
			backend.pathConfigRoot(),
			backend.pathConfigLease(),
			backend.pathListRoles(),
			backend.pathRole(),
			backend.pathAPIKey(),
		},
		Secrets:        []*framework.Secret{backend.secretAPIKey()},
		RunningVersion: version.Version,
	}

	backend.exo = &exoscale{}
	if err := backend.exo.LoadConfigFromStorage(ctx, config.StorageView); err != nil {
		return nil, err
	}

	if err := backend.Setup(ctx, config); err != nil {
		return nil, err
	}

	return &backend, nil
}

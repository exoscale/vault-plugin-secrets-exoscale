package exoscale

import (
	"context"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"

	"github.com/exoscale/vault-plugin-secrets-exoscale/version"
)

type exoscaleBackend struct {
	exo *Exoscale
	*framework.Backend
}

func Factory(ctx context.Context, config *logical.BackendConfig) (logical.Backend, error) {
	backend := exoscaleBackend{exo: &Exoscale{}}
	backend.Backend = &framework.Backend{
		BackendType: logical.TypeLogical,
		Help:        "Dynamically create Exoscale IAM API Keys",
		Paths: framework.PathAppend(
			backend.pathRole(),
			[]*framework.Path{
				backend.pathConfigRoot(),
				backend.pathConfigLease(),
				backend.pathAPIKey(),
			},
		),
		Secrets:        []*framework.Secret{backend.secretAPIKey()},
		RunningVersion: version.Version,
		InitializeFunc: func(ctx context.Context, ir *logical.InitializationRequest) error {
			return backend.exo.LoadConfigFromStorage(ctx, ir.Storage)
		},
	}

	if err := backend.Setup(ctx, config); err != nil {
		return nil, err
	}

	return &backend, nil
}

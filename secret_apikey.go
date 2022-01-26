package exoscale

import (
	"context"
	"errors"
	"fmt"

	egoscale "github.com/exoscale/egoscale/v2"
	exoapi "github.com/exoscale/egoscale/v2/api"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const SecretTypeAPIKey = "apikey"

func secretAPIKey(b *exoscaleBackend) *framework.Secret {
	return &framework.Secret{
		Type: SecretTypeAPIKey,
		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeString,
				Description: "API key name",
			},
			"api_key": {
				Type:        framework.TypeString,
				Description: "API key",
			},
			"api_secret": {
				Type:        framework.TypeString,
				Description: "API secret",
			},
		},

		Renew:  b.secretAPIKeyRenew,
		Revoke: b.secretAPIKeyRevoke,
	}
}

func (b *exoscaleBackend) secretAPIKeyRenew(
	ctx context.Context,
	req *logical.Request,
	_ *framework.FieldData,
) (*logical.Response, error) {
	roleName, ok := req.Secret.InternalData["role"]
	if !ok {
		return nil, fmt.Errorf("secret is missing the role field in its internal data")
	}

	role, err := b.roleConfig(ctx, req.Storage, roleName.(string))
	if err != nil {
		return nil, fmt.Errorf("error retrieving role: %w", err)
	}
	if role == nil {
		return logical.ErrorResponse(fmt.Sprintf("role %q not found", roleName)), nil
	}

	lc, err := b.leaseConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if lc == nil {
		lc = new(leaseConfig)
	}

	if role.LeaseConfig != nil {
		lc = role.LeaseConfig
	}

	ttl, _, err := framework.CalculateTTL(b.System(), req.Secret.Increment, role.LeaseConfig.TTL, 0, role.LeaseConfig.MaxTTL, 0, req.Secret.IssueTime)
	if err != nil {
		return nil, err
	}

	res := &logical.Response{Secret: req.Secret}
	res.Secret.TTL = ttl
	res.Secret.MaxTTL = lc.MaxTTL

	return res, nil
}

func (b *exoscaleBackend) secretAPIKeyRevoke(
	ctx context.Context,
	req *logical.Request,
	_ *framework.FieldData,
) (*logical.Response, error) {
	if b.exo == nil {
		return nil, errors.New("backend is not configured")
	}

	config, err := b.config(ctx, req.Storage)
	if err != nil {
		return nil, fmt.Errorf("unable to retrieve backend configuration: %w", err)
	}

	k, ok := req.Secret.InternalData["api_key"]
	if !ok {
		return nil, errors.New("API key is missing from the secret")
	}
	key := k.(string)

	if err = b.exo.RevokeIAMAccessKey(
		exoapi.WithEndpoint(ctx, exoapi.NewReqEndpoint(config.APIEnvironment, config.Zone)),
		config.Zone,
		&egoscale.IAMAccessKey{Key: &key},
	); err != nil {
		return nil, fmt.Errorf("unable to revoke the API key: %w", err)
	}

	return nil, nil
}

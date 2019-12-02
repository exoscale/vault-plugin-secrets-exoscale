package exoscale

import (
	"context"

	"github.com/exoscale/egoscale"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/pkg/errors"
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

func (b *exoscaleBackend) secretAPIKeyRenew(ctx context.Context, req *logical.Request,
	data *framework.FieldData) (*logical.Response, error) {
	lc, err := b.leaseConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if lc == nil {
		lc = new(leaseConfig)
	}

	res := &logical.Response{Secret: req.Secret}
	res.Secret.TTL = lc.TTL
	res.Secret.MaxTTL = lc.MaxTTL

	return res, nil
}

func (b *exoscaleBackend) secretAPIKeyRevoke(ctx context.Context, req *logical.Request,
	data *framework.FieldData) (*logical.Response, error) {
	if b.exo == nil {
		return nil, errors.New("backend is not configured")
	}

	key, ok := req.Secret.InternalData["api_key"]
	if !ok {
		return nil, errors.New("API key is missing from the secret")
	}

	if _, err := b.exo.RequestWithContext(ctx, &egoscale.RevokeAPIKey{Key: key.(string)}); err != nil {
		return nil, errors.Wrap(err, "unable to revoke the API key")
	}

	return nil, nil
}

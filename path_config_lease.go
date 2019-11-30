package exoscale

import (
	"context"
	"github.com/pkg/errors"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const configLeaseStoragePath = "config/lease"

var pathConfigLeaseHelpSyn = "Configure the backend-specific secrets lease parameters"
var pathConfigLeaseHelpDesc = `
This endpoint manages the secrets lease duration applied to generated API key
secrets. If not configured, global system lease values are applied to generated
secrets.

Note: it is not possible to configure a lease duration greater than the
system's defaults.
`

func pathConfigLease(b *exoscaleBackend) *framework.Path {
	return &framework.Path{
		Pattern: "config/lease",
		Fields: map[string]*framework.FieldSchema{
			"ttl": &framework.FieldSchema{
				Type:        framework.TypeDurationSecond,
				Description: "Duration of issued API key secrets",
			},
			"max_ttl": &framework.FieldSchema{
				Type:        framework.TypeDurationSecond,
				Description: `Duration after which the issued API key secrets are not allowed to be renewed`,
			},
		},

		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.ReadOperation:   b.pathLeaseRead,
			logical.UpdateOperation: b.pathLeaseUpdate,
			logical.DeleteOperation: b.pathLeaseDelete,
		},

		HelpSynopsis:    pathConfigLeaseHelpSyn,
		HelpDescription: pathConfigLeaseHelpDesc,
	}
}

func (b *exoscaleBackend) leaseConfig(ctx context.Context, storage logical.Storage) (*leaseConfig, error) {
	var leaseConfig leaseConfig

	entry, err := storage.Get(ctx, configLeaseStoragePath)
	if err != nil {
		return nil, errors.Wrapf(err, "error retrieving lease configuration")
	}
	if entry == nil {
		return nil, nil
	}

	if err := entry.DecodeJSON(&leaseConfig); err != nil {
		return nil, err
	}

	return &leaseConfig, nil
}

func (b *exoscaleBackend) pathLeaseRead(ctx context.Context, req *logical.Request,
	data *framework.FieldData) (*logical.Response, error) {
	lease, err := b.leaseConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if lease == nil {
		return nil, nil
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"ttl":     int64(lease.TTL.Seconds()),
			"max_ttl": int64(lease.MaxTTL.Seconds()),
		},
	}, nil
}

func (b *exoscaleBackend) pathLeaseUpdate(ctx context.Context, req *logical.Request,
	data *framework.FieldData) (*logical.Response, error) {
	entry, err := logical.StorageEntryJSON(configLeaseStoragePath, &leaseConfig{
		TTL:    time.Second * time.Duration(data.Get("ttl").(int)),
		MaxTTL: time.Second * time.Duration(data.Get("max_ttl").(int)),
	})
	if err != nil {
		return nil, err
	}
	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, err
	}

	return nil, nil
}

func (b *exoscaleBackend) pathLeaseDelete(ctx context.Context, req *logical.Request,
	data *framework.FieldData) (*logical.Response, error) {
	if err := req.Storage.Delete(ctx, configLeaseStoragePath); err != nil {
		return nil, err
	}

	return nil, nil
}

type leaseConfig struct {
	TTL    time.Duration `json:"ttl" mapstructure:"ttl"`
	MaxTTL time.Duration `json:"max_ttl" mapstructure:"max_ttl"`
}

package exoscale

import (
	"context"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const configLeaseStoragePath = "config/lease"

const (
	pathConfigLeaseHelpSyn  = "Configure the backend-specific secrets lease parameters"
	pathConfigLeaseHelpDesc = `
This endpoint manages the secrets lease duration applied to generated API key
secrets. If not configured, global system lease values are applied to generated
secrets.

Note: it is not possible to configure a lease duration greater than the
system's defaults.
`
)

func (b *exoscaleBackend) pathConfigLease() *framework.Path {
	return &framework.Path{
		Pattern: "config/lease",
		Fields: map[string]*framework.FieldSchema{
			"ttl": {
				Type:        framework.TypeDurationSecond,
				Description: "Duration of issued API key secrets",
			},
			"max_ttl": {
				Type:        framework.TypeDurationSecond,
				Description: `Duration after which the issued API key secrets are not allowed to be renewed`,
			},
		},

		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation:   &framework.PathOperation{Callback: b.pathLeaseRead},
			logical.UpdateOperation: &framework.PathOperation{Callback: b.pathLeaseWrite},
			logical.DeleteOperation: &framework.PathOperation{Callback: b.pathLeaseDelete},
		},

		HelpSynopsis:    pathConfigLeaseHelpSyn,
		HelpDescription: pathConfigLeaseHelpDesc,
	}
}

func (b *exoscaleBackend) leaseConfig(ctx context.Context, storage logical.Storage) (*leaseConfig, error) {
	var lc leaseConfig

	entry, err := storage.Get(ctx, configLeaseStoragePath)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}

	if err := entry.DecodeJSON(&lc); err != nil {
		return nil, err
	}

	return &lc, nil
}

func (b *exoscaleBackend) pathLeaseRead(
	ctx context.Context,
	req *logical.Request,
	_ *framework.FieldData,
) (*logical.Response, error) {
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

func (b *exoscaleBackend) pathLeaseWrite(
	ctx context.Context,
	req *logical.Request,
	data *framework.FieldData,
) (*logical.Response, error) {
	ttl, hasTTL := data.GetOk("ttl")
	maxTTL, hasMaxTTL := data.GetOk("max_ttl")
	if !hasTTL || !hasMaxTTL {
		return logical.ErrorResponse(`"ttl" and "max_ttl" must both be specified`), nil
	}
	if ttl.(int) == 0 || maxTTL.(int) == 0 {
		return logical.ErrorResponse(`"ttl" and "max_ttl" value must be greater than 0`), nil
	}

	entry, err := logical.StorageEntryJSON(configLeaseStoragePath, &leaseConfig{
		TTL:    time.Second * time.Duration(ttl.(int)),
		MaxTTL: time.Second * time.Duration(maxTTL.(int)),
	})
	if err != nil {
		return nil, err
	}
	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, err
	}

	return nil, nil
}

func (b *exoscaleBackend) pathLeaseDelete(
	ctx context.Context,
	req *logical.Request,
	_ *framework.FieldData,
) (*logical.Response, error) {
	if err := req.Storage.Delete(ctx, configLeaseStoragePath); err != nil {
		return nil, err
	}

	return nil, nil
}

type leaseConfig struct {
	TTL    time.Duration `json:"ttl"`
	MaxTTL time.Duration `json:"max_ttl"`
}

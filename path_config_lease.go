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
	pathConfigLeaseHelpDesc = `Manages the default secrets lease duration.
Can be overridden by the role settings.

⚠️ WARNING⚠️  This setting only applies to legacy IAM access key,
new API keys should take advantage of the "vault secrets tune" command:
- vault secrets tune -default-lease-ttl=4m -max-lease-ttl=8m exoscale
- vault read sys/mounts/exoscale/tune


If not configured, global system lease values are applied to generated
secrets.
(note: it is not possible to configure a lease duration greater than the
system's defaults)
`
)

func (b *exoscaleBackend) pathConfigLease() *framework.Path {
	return &framework.Path{
		Pattern: "config/lease",
		Fields: map[string]*framework.FieldSchema{
			"ttl": {
				Type: framework.TypeDurationSecond,
				Description: `Duration of issued API key secrets
				If not set or set to 0, will use system default`,
			},
			"max_ttl": {
				Type: framework.TypeDurationSecond,
				Description: `Duration after which the issued API key secrets are not allowed to be renewed
				If not set or set to 0, will use system default`,
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

func getLeaseConfig(ctx context.Context, storage logical.Storage) (leaseConfig, error) {
	var lc leaseConfig

	entry, err := storage.Get(ctx, configLeaseStoragePath)
	if err != nil {
		return leaseConfig{}, err
	}
	if entry == nil {
		return leaseConfig{}, nil
	}

	if err := entry.DecodeJSON(&lc); err != nil {
		return leaseConfig{}, err
	}

	return lc, nil
}

func (b *exoscaleBackend) pathLeaseRead(
	ctx context.Context,
	req *logical.Request,
	_ *framework.FieldData,
) (*logical.Response, error) {
	lc, err := getLeaseConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	res := &logical.Response{
		Data: map[string]interface{}{
			"ttl":     int64(lc.TTL.Seconds()),
			"max_ttl": int64(lc.MaxTTL.Seconds()),
		},
	}

	res.AddWarning(`This setting only applies to legacy IAM access key,
new API keys should take advantage of the "vault secrets tune" command`)

	return res, nil
}

func (b *exoscaleBackend) pathLeaseWrite(
	ctx context.Context,
	req *logical.Request,
	data *framework.FieldData,
) (*logical.Response, error) {
	lc, err := getLeaseConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	if ttl, ok := data.GetOk("ttl"); ok {
		lc.TTL = time.Duration(ttl.(int)) * time.Second
	}
	if maxTTL, ok := data.GetOk("max_ttl"); ok {
		lc.MaxTTL = time.Duration(maxTTL.(int)) * time.Second
	}

	entry, err := logical.StorageEntryJSON(configLeaseStoragePath, lc)
	if err != nil {
		return nil, err
	}

	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, err
	}

	res := &logical.Response{
		Data: map[string]interface{}{
			"ttl":     int64(lc.TTL.Seconds()),
			"max_ttl": int64(lc.MaxTTL.Seconds()),
		},
	}

	res.AddWarning(`This setting only applies to legacy IAM access key,
new API keys should take advantage of the "vault secrets tune" command`)

	return res, nil
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

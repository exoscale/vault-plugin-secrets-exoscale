package exoscale

import (
	"context"

	"github.com/exoscale/egoscale"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/pkg/errors"
)

const (
	configRootStoragePath = "config/root"

	configKeyAPIEndpoint   = "api_endpoint"
	configKeyRootAPIKey    = "root_api_key"
	configKeyRootAPISecret = "root_api_secret"

	defaultAPIEndpoint = "https://api.exoscale.com/v1"
)

var (
	pathConfigRootHelpSyn  = "Configure the root Exoscale API credentials"
	pathConfigRootHelpDesc = `
This endpoint manages the backend configuration of the root Exoscale API
credentials used by Vault to interact with the Exoscale IAM API in order to
perform API key secrets handling.

Note: if the configured root Exoscale API key is itself restricted to specific
API operations, the backend won't be able to issue API keys with broader
permissions than what the root API key is allowed to. To be able to issue API
keys granting all Exoscale API operations, configure the backend with an
unrestricted root API key and define role to restrict API key secrets to
specific API operations (see the <mountpoint>/role/_ endpoint for more
information).
`
)

var errMissingAPICredentials = errors.New("missing root API credentials")

func pathConfigRoot(b *exoscaleBackend) *framework.Path {
	return &framework.Path{
		Pattern: "config/root",
		Fields: map[string]*framework.FieldSchema{
			configKeyAPIEndpoint: {
				Type:        framework.TypeString,
				Description: "Exoscale API endpoint",
			},
			configKeyRootAPIKey: {
				Type:         framework.TypeString,
				Description:  "Exoscale API key",
				DisplayAttrs: &framework.DisplayAttributes{Sensitive: true},
			},
			configKeyRootAPISecret: {
				Type:         framework.TypeString,
				Description:  "Exoscale API secret",
				DisplayAttrs: &framework.DisplayAttributes{Sensitive: true},
			},
		},

		Operations: map[logical.Operation]framework.OperationHandler{
			logical.CreateOperation: &framework.PathOperation{Callback: b.pathConfigWrite},
			logical.UpdateOperation: &framework.PathOperation{Callback: b.pathConfigWrite},
			logical.ReadOperation:   &framework.PathOperation{Callback: b.pathConfigRead},
		},

		HelpSynopsis:    pathConfigRootHelpSyn,
		HelpDescription: pathConfigRootHelpDesc,
	}
}

func (b *exoscaleBackend) backendConfig(ctx context.Context, storage logical.Storage) (*backendConfig, error) {
	var config backendConfig

	entry, err := storage.Get(ctx, configRootStoragePath)
	if err != nil {
		return nil, errors.Wrapf(err, "error retrieving backend configuration")
	}
	if entry == nil {
		return nil, nil
	}

	if err := entry.DecodeJSON(&config); err != nil {
		return nil, err
	}

	return &config, nil
}

func (b *exoscaleBackend) pathConfigRead(ctx context.Context, req *logical.Request,
	_ *framework.FieldData) (*logical.Response, error) {
	config, err := b.backendConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	} else if config == nil {
		return nil, nil
	}

	return &logical.Response{
		Data: map[string]interface{}{
			configKeyAPIEndpoint:   config.APIEndpoint,
			configKeyRootAPIKey:    config.RootAPIKey,
			configKeyRootAPISecret: config.RootAPISecret,
		},
	}, nil
}

func (b *exoscaleBackend) pathConfigWrite(ctx context.Context, req *logical.Request,
	data *framework.FieldData) (*logical.Response, error) {
	config := &backendConfig{APIEndpoint: defaultAPIEndpoint}

	if v, ok := data.GetOk(configKeyAPIEndpoint); ok {
		config.APIEndpoint = v.(string)
	}
	if v, ok := data.GetOk(configKeyRootAPIKey); ok {
		config.RootAPIKey = v.(string)
	}
	if v, ok := data.GetOk(configKeyRootAPISecret); ok {
		config.RootAPISecret = v.(string)
	}

	if config.RootAPIKey == "" || config.RootAPISecret == "" {
		return nil, errMissingAPICredentials
	}

	entry, err := logical.StorageEntryJSON(configRootStoragePath, config)
	if err != nil {
		return nil, err
	}

	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, err
	}

	b.exo = egoscale.NewClient(config.APIEndpoint, config.RootAPIKey, config.RootAPISecret)

	res := &logical.Response{}
	res.AddWarning("Read access to this endpoint should be controlled via ACLs as " +
		"it will return sensitive information as-is, including the root API credentials")

	return res, nil
}

type backendConfig struct {
	APIEndpoint   string `json:"api_endpoint"`
	RootAPIKey    string `json:"root_api_key"`
	RootAPISecret string `json:"root_api_secret"`
}

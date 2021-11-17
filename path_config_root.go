package exoscale

import (
	"context"
	"errors"
	"fmt"

	egoscale "github.com/exoscale/egoscale/v2"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const (
	configRootStoragePath = "config/root"

	configAPIEnvironment = "api_environment"
	configRootAPIKey     = "root_api_key"
	configRootAPISecret  = "root_api_secret"
	configZone           = "zone"

	defaultAPIEnvironment = "api"
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

	errMissingAPICredentials = errors.New("missing root API credentials")
	errMissingZone           = errors.New("missing zone")
)

func pathConfigRoot(b *exoscaleBackend) *framework.Path {
	return &framework.Path{
		Pattern: "config/root",
		Fields: map[string]*framework.FieldSchema{
			configAPIEnvironment: {
				Type:        framework.TypeString,
				Description: "Exoscale API environment",
				Default:     defaultAPIEnvironment,
			},
			configRootAPIKey: {
				Type:         framework.TypeString,
				Description:  "Exoscale API key",
				DisplayAttrs: &framework.DisplayAttributes{Sensitive: true},
			},
			configRootAPISecret: {
				Type:         framework.TypeString,
				Description:  "Exoscale API secret",
				DisplayAttrs: &framework.DisplayAttributes{Sensitive: true},
			},
			configZone: {
				Type:        framework.TypeString,
				Description: "Exoscale zone",
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

func (b *exoscaleBackend) config(ctx context.Context, storage logical.Storage) (*backendConfig, error) {
	var config backendConfig

	entry, err := storage.Get(ctx, configRootStoragePath)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}

	if err := entry.DecodeJSON(&config); err != nil {
		return nil, err
	}

	return &config, nil
}

func (b *exoscaleBackend) pathConfigRead(
	ctx context.Context,
	req *logical.Request,
	_ *framework.FieldData,
) (*logical.Response, error) {
	config, err := b.config(ctx, req.Storage)
	if err != nil {
		return nil, err
	} else if config == nil {
		return nil, nil
	}

	return &logical.Response{
		Data: map[string]interface{}{
			configAPIEnvironment: config.APIEnvironment,
			configRootAPIKey:     config.RootAPIKey,
			configRootAPISecret:  config.RootAPISecret,
			configZone:           config.Zone,
		},
	}, nil
}

func (b *exoscaleBackend) pathConfigWrite(
	ctx context.Context,
	req *logical.Request,
	data *framework.FieldData,
) (*logical.Response, error) {
	config := &backendConfig{
		APIEnvironment: data.Get(configAPIEnvironment).(string),
		RootAPIKey:     data.Get(configRootAPIKey).(string),
		RootAPISecret:  data.Get(configRootAPISecret).(string),
		Zone:           data.Get(configZone).(string),
	}

	if v, ok := data.GetOk(configAPIEnvironment); ok {
		config.APIEnvironment = v.(string)
	}

	if config.RootAPIKey == "" || config.RootAPISecret == "" {
		return nil, errMissingAPICredentials
	}

	if config.Zone == "" {
		return nil, errMissingZone
	}

	entry, err := logical.StorageEntryJSON(configRootStoragePath, config)
	if err != nil {
		return nil, err
	}

	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, err
	}

	exo, err := egoscale.NewClient(config.RootAPIKey, config.RootAPISecret)
	if err != nil {
		return nil, fmt.Errorf("unable to initialize Exoscale client: %w", err)
	}
	b.exo = exo

	res := &logical.Response{}
	res.AddWarning("Read access to this endpoint should be controlled via ACLs as " +
		"it will return sensitive information as-is, including the root API credentials")

	return res, nil
}

type backendConfig struct {
	APIEnvironment string `json:"api_environment"`
	RootAPIKey     string `json:"root_api_key"`
	RootAPISecret  string `json:"root_api_secret"`
	Zone           string `json:"zone"`
}

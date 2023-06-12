package exoscale

import (
	"context"
	"errors"

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
Configure the root Exoscale API credentials used by Vault to interact with
the Exoscale IAM API in order to perform API key secrets handling.

Note: if the configured root Exoscale API key is itself restricted to specific
API operations, the backend won't be able to issue API keys with broader
permissions than what the root API key is allowed to.

To be able to issue API keys granting all Exoscale API operations, configure
the backend with an unrestricted root API key.
`

	errMissingAPICredentials = errors.New("missing root API credentials")
	errMissingZone           = errors.New("missing zone")
)

func (b *exoscaleBackend) pathConfigRoot() *framework.Path {
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
				Description: "Exoscale API zone",
			},
		},

		Operations: map[logical.Operation]framework.OperationHandler{
			logical.CreateOperation: &framework.PathOperation{Callback: b.pathConfigRootWrite},
			logical.UpdateOperation: &framework.PathOperation{Callback: b.pathConfigRootWrite},
			logical.ReadOperation:   &framework.PathOperation{Callback: b.pathConfigRootRead},
		},

		HelpSynopsis:    pathConfigRootHelpSyn,
		HelpDescription: pathConfigRootHelpDesc,
	}
}

func (b *exoscaleBackend) pathConfigRootRead(
	ctx context.Context,
	req *logical.Request,
	_ *framework.FieldData,
) (*logical.Response, error) {
	if !b.exo.configured {
		return nil, nil
	}

	return &logical.Response{
		Data: map[string]interface{}{
			configAPIEnvironment: b.exo.reqEndpoint.Env(),
			configRootAPIKey:     b.exo.egoscaleClient,
			configZone:           b.exo.reqEndpoint.Zone,
		},
	}, nil
}

func (b *exoscaleBackend) pathConfigRootWrite(
	ctx context.Context,
	req *logical.Request,
	data *framework.FieldData,
) (*logical.Response, error) {
	config := rootConfig{
		APIEnvironment: data.Get(configAPIEnvironment).(string),
		RootAPIKey:     data.Get(configRootAPIKey).(string),
		RootAPISecret:  data.Get(configRootAPISecret).(string),
		Zone:           data.Get(configZone).(string),
	}

	if config.RootAPIKey == "" || config.RootAPISecret == "" {
		return nil, errMissingAPICredentials
	}

	if config.Zone == "" {
		config.Zone = "ch-gva-2"
	}

	entry, err := logical.StorageEntryJSON(configRootStoragePath, config)
	if err != nil {
		return nil, err
	}

	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, err
	}

	if err := b.exo.LoadConfig(config); err != nil {
		return nil, err
	}

	return nil, nil
}

type rootConfig struct {
	APIEnvironment string `json:"api_environment"`
	RootAPIKey     string `json:"root_api_key"`
	RootAPISecret  string `json:"root_api_secret"`
	Zone           string `json:"zone"`
}

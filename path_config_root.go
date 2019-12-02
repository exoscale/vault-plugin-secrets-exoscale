package exoscale

import (
	"context"
	"errors"

	"github.com/exoscale/egoscale"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const (
	configRootStoragePath = "config/root"

	defaultAPIEndpoint = "https://api.exoscale.com/compute"
)

var pathConfigRootHelpSyn = "Configure the root Exoscale API credentials"
var pathConfigRootHelpDesc = `
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

var errMissingAPICredentials = errors.New("missing root API credentials")

func pathConfigRoot(b *exoscaleBackend) *framework.Path {
	return &framework.Path{
		Pattern: "config/root",
		Fields: map[string]*framework.FieldSchema{
			"api_endpoint": {
				Type:        framework.TypeString,
				Description: "Exoscale API endpoint",
			},
			"root_api_key": {
				Type:        framework.TypeString,
				Description: "Exoscale API key",
			},
			"root_api_secret": {
				Type:        framework.TypeString,
				Description: "Exoscale API secret",
			},
		},

		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.CreateOperation: b.pathConfigWrite,
			logical.UpdateOperation: b.pathConfigWrite,
			logical.ReadOperation:   b.pathConfigRead,
		},

		HelpSynopsis:    pathConfigRootHelpSyn,
		HelpDescription: pathConfigRootHelpDesc,
	}
}

func (b *exoscaleBackend) pathConfigRead(ctx context.Context, req *logical.Request,
	data *framework.FieldData) (*logical.Response, error) {

	config, err := b.config(ctx, req.Storage)
	if err != nil {
		return nil, err
	} else if config == nil {
		return nil, nil
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"api_endpoint":    config.APIEndpoint,
			"root_api_key":    config.RootAPIKey,
			"root_api_secret": config.RootAPISecret,
		},
	}, nil
}

func (b *exoscaleBackend) pathConfigWrite(ctx context.Context, req *logical.Request,
	data *framework.FieldData) (*logical.Response, error) {

	config := &backendConfig{APIEndpoint: defaultAPIEndpoint}

	if v, ok := data.GetOk("api_endpoint"); ok {
		config.APIEndpoint = v.(string)
	}
	if v, ok := data.GetOk("root_api_key"); ok {
		config.RootAPIKey = v.(string)
	}
	if v, ok := data.GetOk("root_api_secret"); ok {
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

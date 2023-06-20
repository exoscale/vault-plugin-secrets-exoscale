package exoscale

import (
	"context"
	"errors"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const (
	configRootStoragePath = "config/root"

	configAPIEnvironment   = "api_environment"
	configRootAPIKey       = "root_api_key"
	configRootAPISecret    = "root_api_secret"
	configZone             = "zone"
	configAPIKeyNamePrefix = "api_key_name_prefix"
)

var (
	pathConfigRootHelpSyn  = "Configure the root Exoscale API credentials"
	pathConfigRootHelpDesc = `
Configure the root Exoscale API credentials that will be used to manage the IAM Keys
that are handled by Vault.

This plugin currently supports both our new IAM API Keys (referred to as "v3 API key" in our API)
and our legacy IAM keys (referred to as "IAM Access Key" in our API)

IAM API Keys (recommended)
==========================
The root API Key must have the permissions to perform the following IAM operations:
create-api-key, delete-api-key, get-api-key, list-api-keys, list-iam-roles, get-iam-role"

This can be achieved with the following role policy :

{
  "default-service-strategy": "deny",
  "services": {
    "compute": {
      "type": "rules",
      "rules": [
        {
          "expression": "operation == 'get-operation'",
          "action": "allow"
        }
      ]
    },
    "iam": {
      "type": "rules",
      "rules": [
        {
          "expression": "operation in ['create-api-key', 'delete-api-key', 'get-api-key', 'list-api-keys', 'list-iam-roles', 'get-iam-role']",
          "action": "allow"
        }
      ]
    }
  }
}

It is possible to restrict the creation of keys to a predefined list of roles by using the
parameters.role_id variable in the CEL expression, please refer to the IAM documentation for more information.

Legacy IAM Access Keys (deprecated)
===================================
With legacy IAM the Access Keys that are created must have a subset of the permissions of the
root access key. If you want to create any access key, the root key must be unrestricted.
`
	errMissingAPICredentials = errors.New("missing root API root_api_key or root_api_secret")
)

type ExoscaleConfig struct {
	APIEnvironment   string `json:"api_environment"`
	RootAPIKey       string `json:"root_api_key"`
	RootAPISecret    string `json:"root_api_secret"`
	Zone             string `json:"zone"`
	APIKeyNamePrefix string `json:"api_key_name_prefix"`
}

func (b *exoscaleBackend) pathConfigRoot() *framework.Path {
	return &framework.Path{
		Pattern: "config/root",
		Fields: map[string]*framework.FieldSchema{
			configAPIEnvironment: {
				Type:        framework.TypeString,
				Description: "used only by the plugin developers, do not set",
				Default:     "api",
			},
			configRootAPIKey: {
				Type:         framework.TypeString,
				Description:  "Exoscale API key (required)",
				DisplayAttrs: &framework.DisplayAttributes{Sensitive: true},
			},
			configRootAPISecret: {
				Type:         framework.TypeString,
				Description:  "Exoscale API secret (required)",
				DisplayAttrs: &framework.DisplayAttributes{Sensitive: true},
			},
			configAPIKeyNamePrefix: {
				Type: framework.TypeString,
				Description: `Adds a prefix to the token name, just after 'vault'
				e.g. with api_key_name_prefix=example the token name will be "vault-example-myrole-authname-0000000000000000000"
				instead of "vault-myrole-authname-0000000000000000000" without (optional)`,
				Default: "",
			},
			configZone: {
				Type: framework.TypeString,
				Description: `Exoscale API zone (optional, default: ch-gva-2)
note: API Keys are global, this only changes the zone used to perform API calls`,
				Default: "ch-gva-2",
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
		return nil, ErrorBackendNotConfigured
	}

	return &logical.Response{
		Data: map[string]interface{}{
			configAPIEnvironment:   b.exo.reqEndpoint.Env(),
			configRootAPIKey:       b.exo.apiKey,
			configRootAPISecret:    b.exo.apiSecret,
			configZone:             b.exo.reqEndpoint.Zone(),
			configAPIKeyNamePrefix: b.exo.apiKeyNamePrefix,
		},
	}, nil
}

func (b *exoscaleBackend) pathConfigRootWrite(
	ctx context.Context,
	req *logical.Request,
	data *framework.FieldData,
) (*logical.Response, error) {
	config := ExoscaleConfig{
		APIEnvironment:   data.Get(configAPIEnvironment).(string),
		Zone:             data.Get(configZone).(string),
		APIKeyNamePrefix: data.Get(configAPIKeyNamePrefix).(string),
		RootAPIKey:       data.Get(configRootAPIKey).(string),
		RootAPISecret:    data.Get(configRootAPISecret).(string),
	}

	if config.RootAPIKey == "" || config.RootAPISecret == "" {
		return nil, errMissingAPICredentials
	}

	entry, err := logical.StorageEntryJSON(configRootStoragePath, config)
	if err != nil {
		return nil, err
	}

	if err := b.exo.LoadConfig(config); err != nil {
		return nil, err
	}

	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, err
	}

	res := &logical.Response{
		Data: map[string]interface{}{
			configAPIEnvironment:   b.exo.reqEndpoint.Env(),
			configRootAPIKey:       b.exo.apiKey,
			configRootAPISecret:    b.exo.apiSecret,
			configZone:             b.exo.reqEndpoint.Zone(),
			configAPIKeyNamePrefix: b.exo.apiKeyNamePrefix,
		},
	}
	res.AddWarning("Access to the /config/root endpoint should be controlled via ACLs as it will return sensitive informations")

	return res, nil
}

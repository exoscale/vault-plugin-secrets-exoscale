package exoscale

import (
	"context"
	"fmt"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const (
	apiKeySecretDataName      = "name"
	apiKeySecretDataAPIKey    = "api_key"
	apiKeySecretDataAPISecret = "api_secret"
)

const (
	pathAPIKeyHelpSyn  = "Issue new Exoscale API key/secret credentials"
	pathAPIKeyHelpDesc = `
This endpoint dynamically generates Exoscale API key/secret credentials based
on a role, depending on which the generated API key will be restricted to
certain API operations.

Note: the backend doesn't store the generated API credentials, there is no way
to recover an API secret after it's been returned during the secret creation.
`
)

func (b *exoscaleBackend) pathAPIKey() *framework.Path {
	return &framework.Path{
		Pattern: "apikey/" + framework.GenericNameRegex("role"),
		Fields: map[string]*framework.FieldSchema{
			"role": {
				Type:        framework.TypeString,
				Description: "Name of the vault role to use to create the API key",
			},
		},

		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{Callback: b.createAPIKey},
		},

		HelpSynopsis:    pathAPIKeyHelpSyn,
		HelpDescription: pathAPIKeyHelpDesc,
	}
}

func (b *exoscaleBackend) createAPIKey(
	ctx context.Context,
	req *logical.Request,
	data *framework.FieldData,
) (*logical.Response, error) {
	roleName := data.Get("role").(string)

	role, err := getRole(ctx, req.Storage, roleName)
	if err != nil {
		return nil, fmt.Errorf("error retrieving role %q: %w", roleName, err)
	} else if role == nil {
		return logical.ErrorResponse("role %q not found", roleName), nil
	}

	var res *logical.Response
	if role.Version == "v2" {
		apikey, err := b.exo.V2CreateAccessKey(ctx, roleName, req.DisplayName, *role)
		if err != nil {
			return nil, err
		}

		lc, err := getLeaseConfig(ctx, req.Storage)
		if err != nil {
			return nil, err
		}

		if role.TTL != 0 {
			lc.TTL = role.TTL
		}
		if role.MaxTTL != 0 {
			lc.MaxTTL = role.MaxTTL
		}

		res = b.Secret(SecretTypeAPIKey).Response(
			// Information returned to the requester
			map[string]interface{}{
				apiKeySecretDataName:      *apikey.Name,
				apiKeySecretDataAPIKey:    *apikey.Key,
				apiKeySecretDataAPISecret: *apikey.Secret,
			},
			// Information for internal use (e.g. revoke)
			map[string]interface{}{
				apiKeySecretDataAPIKey: *apikey.Key,
				"role":                 roleName,
				"expireTime":           time.Now().Add(lc.TTL),
				"name":                 *apikey.Name,
			})

		res.Secret.TTL = lc.TTL
		res.Secret.MaxTTL = lc.MaxTTL
		res.Secret.Renewable = role.Renewable

		b.Logger().Info("Creating IAMv2 secret",
			"ttl", fmt.Sprint(lc.TTL),
			"max_ttl", fmt.Sprint(lc.MaxTTL),
			"role", roleName,
			"iam_key", *apikey.Key,
			"iam_name", *apikey.Name,
			"renewable", res.Secret.Renewable)
	} else {
		apikey, err := b.exo.V3CreateAPIKey(ctx, roleName, req.DisplayName, *role)
		if err != nil {
			b.Logger().Info("Failed to create IAMv3 api key",
				"role", roleName,
				"iam_name", req.DisplayName,
				"err", err)
			return nil, err
		}

		TTL := b.System().DefaultLeaseTTL()
		if role.TTL != 0 {
			TTL = role.TTL
		}

		res = b.Secret(SecretTypeAPIKey).Response(
			// Information returned to the requester
			map[string]interface{}{
				apiKeySecretDataName:      *apikey.Name,
				apiKeySecretDataAPIKey:    *apikey.Key,
				apiKeySecretDataAPISecret: *apikey.Secret,
			},
			// Information for internal use (e.g. revoke)
			map[string]interface{}{
				apiKeySecretDataAPIKey: *apikey.Key,
				"role":                 roleName,
				"expireTime":           time.Now().Add(TTL),
				"name":                 *apikey.Name,
				"version":              role.Version,
			})

		res.Secret.TTL = TTL
		res.Secret.MaxTTL = role.MaxTTL
		res.Secret.Renewable = role.Renewable

		b.Logger().Info("Creating IAMv3 secret",
			"ttl", fmt.Sprint(res.Secret.TTL),
			"max_ttl", fmt.Sprint(res.Secret.MaxTTL),
			"role", roleName,
			"iam_key", *apikey.Key,
			"iam_name", *apikey.Name,
			"iam_role_id", *apikey.RoleId,
			"iam_role_name", role.IAMRoleName,
			"renewable", res.Secret.Renewable)
	}

	return res, nil
}

package exoscale

import (
	"context"
	"errors"
	"fmt"
	"time"

	egoscale "github.com/exoscale/egoscale/v2"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const apiKeyPathPrefix = "apikey/"

var (
	pathAPIKeyHelpSyn  = "Issue new Exoscale API key/secret credentials"
	pathAPIKeyHelpDesc = `
This endpoint dynamically generates Exoscale API key/secret credentials based
on a role, depending on which the generated API key will be restricted to
certain API operations.

Note: the backend doesn't store the generated API credentials, there is no way
to recover an API secret after it's been returned during the secret creation.
`
)

func pathAPIKey(b *exoscaleBackend) *framework.Path {
	return &framework.Path{
		Pattern: apiKeyPathPrefix + framework.GenericNameRegex("role"),
		Fields: map[string]*framework.FieldSchema{
			"role": {
				Type:        framework.TypeString,
				Description: "Name of the role to apply to the API key",
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
	if b.exo == nil {
		return nil, errors.New("backend is not configured")
	}

	config, err := b.config(ctx, req.Storage)
	if err != nil {
		return nil, fmt.Errorf("unable to retrieve backend configuration: %w", err)
	}

	roleName := data.Get("role").(string)

	role, err := b.roleConfig(ctx, req.Storage, roleName)
	if err != nil {
		return nil, fmt.Errorf("error retrieving role %q: %w", roleName, err)
	} else if role == nil {
		return logical.ErrorResponse(fmt.Sprintf("role %q not found", roleName)), nil
	}

	lc, err := b.leaseConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if lc == nil {
		lc = new(leaseConfig)
	}

	// Role-level lease configuration overrides the backend-level configuration
	if role.LeaseConfig != nil {
		lc = role.LeaseConfig
	}

	opts := make([]egoscale.CreateIAMAccessKeyOpt, 0)

	if len(role.Operations) > 0 {
		opts = append(opts, egoscale.CreateIAMAccessKeyWithOperations(role.Operations))
	}

	if len(role.Tags) > 0 {
		opts = append(opts, egoscale.CreateIAMAccessKeyWithTags(role.Tags))
	}

	iamAPIKey, err := b.exo.CreateIAMAccessKey(
		ctx,
		config.Zone,
		fmt.Sprintf("vault-%s-%s-%d", roleName, req.DisplayName, time.Now().UnixNano()),
		opts...,
	)
	if err != nil {
		return nil, fmt.Errorf("unable to create a new API key: %w", err)
	}

	res := b.Secret(SecretTypeAPIKey).Response(map[string]interface{}{
		// Information returned to the requester
		"name":       *iamAPIKey.Name,
		"api_key":    *iamAPIKey.Key,
		"api_secret": *iamAPIKey.Secret,
	},
		// Information for internal use (e.g. to revoke the key later on)
		map[string]interface{}{
			"api_key": *iamAPIKey.Key,
		})
	res.Secret.TTL = lc.TTL
	res.Secret.MaxTTL = lc.MaxTTL

	return res, nil
}

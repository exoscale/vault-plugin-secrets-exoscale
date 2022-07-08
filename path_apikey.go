package exoscale

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	egoscale "github.com/exoscale/egoscale/v2"
	exoapi "github.com/exoscale/egoscale/v2/api"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const (
	apiKeyPathPrefix = "apikey/"

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

	if len(role.Resources) > 0 {
		resources := make([]egoscale.IAMAccessKeyResource, len(role.Resources))
		for i, rs := range role.Resources {
			r, err := parseIAMAccessKeyResource(rs)
			if err != nil {
				return logical.ErrorResponse(fmt.Sprintf("invalid API resource %q", rs)), nil
			}
			resources[i] = *r
		}
		opts = append(opts, egoscale.CreateIAMAccessKeyWithResources(resources))
	}

	if len(role.Tags) > 0 {
		opts = append(opts, egoscale.CreateIAMAccessKeyWithTags(role.Tags))
	}

	iamAPIKey, err := b.exo.CreateIAMAccessKey(
		exoapi.WithEndpoint(ctx, exoapi.NewReqEndpoint(config.APIEnvironment, config.Zone)),
		config.Zone,
		fmt.Sprintf("vault-%s-%s-%d", roleName, req.DisplayName, time.Now().UnixNano()),
		opts...,
	)
	if err != nil {
		return nil, fmt.Errorf("unable to create a new API key: %w", err)
	}

	res := b.Secret(SecretTypeAPIKey).Response(map[string]interface{}{
		// Information returned to the requester
		apiKeySecretDataName:      *iamAPIKey.Name,
		apiKeySecretDataAPIKey:    *iamAPIKey.Key,
		apiKeySecretDataAPISecret: *iamAPIKey.Secret,
	},
		// Information for internal use (e.g. to revoke the key later on)
		map[string]interface{}{
			apiKeySecretDataAPIKey: *iamAPIKey.Key,
			"role":                 roleName,
			"expireTime":           time.Now().Add(lc.TTL),
			"name":                 *iamAPIKey.Name,
		})

	res.Secret.TTL = lc.TTL
	res.Secret.MaxTTL = lc.MaxTTL
	res.Secret.Renewable = role.Renewable

	b.Logger().Info("Creating IAM secret",
		"ttl", fmt.Sprint(lc.TTL),
		"max_ttl", fmt.Sprint(lc.MaxTTL),
		"role", roleName,
		"iam_key", *iamAPIKey.Key,
		"iam_name", *iamAPIKey.Name,
		"renewable", res.Secret.Renewable)

	return res, nil
}

// parseIAMAccessKeyResource parses a string-encoded IAM access key resource formatted such as
// DOMAIN/TYPE:NAME and deserializes it into an egoscale.IAMAccessKeyResource struct.
func parseIAMAccessKeyResource(v string) (*egoscale.IAMAccessKeyResource, error) {
	var iamAccessKeyResource egoscale.IAMAccessKeyResource

	parts := strings.SplitN(v, ":", 2)
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid format")
	}
	iamAccessKeyResource.ResourceName = parts[1]

	parts = strings.SplitN(parts[0], "/", 2)
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid format")
	}
	iamAccessKeyResource.Domain = parts[0]
	iamAccessKeyResource.ResourceType = parts[1]

	if iamAccessKeyResource.Domain == "" ||
		iamAccessKeyResource.ResourceType == "" ||
		iamAccessKeyResource.ResourceName == "" {
		return nil, fmt.Errorf("invalid format")
	}

	return &iamAccessKeyResource, nil
}

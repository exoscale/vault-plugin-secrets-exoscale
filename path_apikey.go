package exoscale

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/exoscale/egoscale"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/pkg/errors"
)

const apiKeyPathPrefix = "apikey/"

var pathAPIKeyHelpSyn = "Issue new Exoscale API key/secret credentials"
var pathAPIKeyHelpDesc = `
This endpoint dynamically generates Exoscale API key/secret credentials based
on a role, depending on which the generated API key will be restricted to
certain API operations.

Note: the backend doesn't store the generated API credentials, there is no way
to recover an API secret after it's been returned during the secret creation.
`

func pathAPIKey(b *exoscaleBackend) *framework.Path {
	return &framework.Path{
		Pattern: apiKeyPathPrefix + framework.GenericNameRegex("role"),
		Fields: map[string]*framework.FieldSchema{
			"role": &framework.FieldSchema{
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

func (b *exoscaleBackend) createAPIKey(ctx context.Context, req *logical.Request,
	data *framework.FieldData) (*logical.Response, error) {
	if b.exo == nil {
		return nil, errors.New("backend is not configured")
	}

	roleName := data.Get("role").(string)

	role, err := b.roleConfig(ctx, req.Storage, roleName)
	if err != nil {
		return nil, errors.Wrapf(err, "error retrieving role %q", roleName)
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

	apiRes, err := b.exo.RequestWithContext(ctx, &egoscale.CreateAPIKey{
		Name:       fmt.Sprintf("vault-%s-%s-%d", roleName, req.DisplayName, time.Now().UnixNano()),
		Operations: strings.Join(role.Operations, ","),
	})
	if err != nil {
		return nil, errors.Wrap(err, "unable to create a new API key")
	}
	apiKey := apiRes.(*egoscale.APIKey)

	res := b.Secret(SecretTypeAPIKey).Response(map[string]interface{}{
		// Information returned to the requester
		"name":       apiKey.Name,
		"api_key":    apiKey.Key,
		"api_secret": apiKey.Secret,
	},
		// Information for internal use (e.g. to revoke the key later on)
		map[string]interface{}{
			"api_key": apiKey.Key,
		})
	res.Secret.TTL = lc.TTL
	res.Secret.MaxTTL = lc.MaxTTL

	return res, nil
}

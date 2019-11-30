package exoscale

import (
	"context"

	"github.com/exoscale/vault-plugin-secrets-exoscale/version"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

var pathInfoHelpSyn = "Display information about this plugin"
var pathInfoHelpDesc = `
This endpoint provides information about the plugin, such as the version and
build commit.
`

func pathInfo(b *exoscaleBackend) *framework.Path {
	return &framework.Path{
		Pattern: "info",
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.ReadOperation: b.pathInfoRead,
		},

		HelpSynopsis:    pathInfoHelpSyn,
		HelpDescription: pathInfoHelpDesc,
	}
}

func (b *exoscaleBackend) pathInfoRead(_ context.Context, req *logical.Request,
	_ *framework.FieldData) (*logical.Response, error) {
	return &logical.Response{
		Data: map[string]interface{}{
			"commit":  version.Commit,
			"version": version.Version,
		},
	}, nil
}

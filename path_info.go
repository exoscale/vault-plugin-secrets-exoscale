package exoscale

import (
	"context"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"

	"github.com/exoscale/vault-plugin-secrets-exoscale/version"
)

var (
	pathInfoHelpSyn  = "Display information about this plugin"
	pathInfoHelpDesc = `
This endpoint provides information about the plugin, such as the version and
build commit.
`
)

func pathInfo(b *exoscaleBackend) *framework.Path {
	return &framework.Path{
		Pattern: "info",

		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{Callback: b.pathInfoRead},
		},

		HelpSynopsis:    pathInfoHelpSyn,
		HelpDescription: pathInfoHelpDesc,
	}
}

func (b *exoscaleBackend) pathInfoRead(_ context.Context, _ *logical.Request,
	_ *framework.FieldData) (*logical.Response, error) {
	return &logical.Response{
		Data: map[string]interface{}{
			"commit":  version.Commit,
			"version": version.Version,
		},
	}, nil
}
